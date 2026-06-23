/// Foundation-free IPv4 / IPv6 textual <-> binary codecs for the QUIC
/// `preferred_address` transport parameter (RFC 9000 §18.2).
///
/// `preferred_address` carries an IPv4 address (4 bytes) and an IPv6 address
/// (16 bytes) on the wire, but the host adapter exposes them as textual
/// strings. The historical adapter used `inet_pton`/`inet_ntop`, which pull in
/// Darwin/Glibc and are unavailable under Embedded Swift. `IPAddressCodec`
/// reimplements the strict parse/format in pure Swift over `[UInt8]`:
/// - IPv4 dotted-decimal <-> 4 bytes,
/// - IPv6 textual (with `::` zero-compression and embedded-IPv4 tail) <-> 16
///   bytes, formatting back in RFC 5952 canonical form (longest zero-run
///   compressed, lowercase hex, leading zeros suppressed).
///
/// The output of `formatIPv6` is byte-for-byte the canonical textual form that
/// `inet_ntop(AF_INET6, …)` produces for the addresses this codec handles, so
/// the adapter's `PreferredAddress.ipv6Address` String round-trips unchanged.
///
/// Embedded-clean: no Foundation, no `inet_pton`/`inet_ntop`, no `any`, no
/// typed throws (every operation is total or returns `nil` on malformed input —
/// the caller maps `nil` to a typed error, never a silent fallback).

public enum IPAddressCodec {

    // MARK: - IPv4

    /// Parses a dotted-decimal IPv4 address (e.g. "192.168.1.1") to its 4
    /// network-order bytes.
    ///
    /// Accepts exactly four decimal octets in `0...255` with no leading-zero
    /// ambiguity beyond a single "0", matching `inet_pton`'s strict form.
    ///
    /// - Returns: The 4 address bytes, or `nil` if not a valid IPv4 literal.
    public static func parseIPv4(_ address: String) -> [UInt8]? {
        let utf8 = Array(address.utf8)
        guard !utf8.isEmpty else { return nil }

        var octets: [UInt8] = []
        octets.reserveCapacity(4)

        var i = 0
        let count = utf8.count
        while true {
            // Parse one octet: 1-3 decimal digits.
            var digits = 0
            var value = 0
            while i < count, let d = decimalValue(utf8[i]) {
                // Reject leading zeros (e.g. "01") to match inet_pton strictness.
                if digits == 1 && value == 0 {
                    return nil
                }
                value = value * 10 + Int(d)
                digits += 1
                i += 1
                if digits > 3 { return nil }
            }
            guard digits > 0, value <= 255 else { return nil }
            octets.append(UInt8(value))

            if octets.count == 4 {
                // Must be at end of string.
                return i == count ? octets : nil
            }

            // Expect a separator dot.
            guard i < count, utf8[i] == UInt8(ascii: ".") else { return nil }
            i += 1
        }
    }

    /// Formats 4 network-order IPv4 bytes as a dotted-decimal string.
    ///
    /// - Returns: The dotted-decimal string, or `nil` if `bytes.count != 4`.
    public static func formatIPv4(_ bytes: [UInt8]) -> String? {
        guard bytes.count == 4 else { return nil }
        var result = ""
        for (index, byte) in bytes.enumerated() {
            if index > 0 { result.append(".") }
            result.append(String(byte))
        }
        return result
    }

    // MARK: - IPv6

    /// Parses an IPv6 address string (e.g. "fe80::1", "::1",
    /// "::ffff:192.0.2.1") to its 16 network-order bytes.
    ///
    /// Supports `::` zero-run compression and a trailing IPv4-dotted-quad
    /// (IPv4-mapped form). Does NOT accept a zone ID.
    ///
    /// - Returns: The 16 address bytes, or `nil` if not a valid IPv6 literal.
    public static func parseIPv6(_ address: String) -> [UInt8]? {
        let utf8 = Array(address.utf8)
        guard !utf8.isEmpty else { return nil }

        // Split into head (before "::") and tail (after "::") group lists.
        // A single "::" compresses one or more all-zero groups.
        var head: [UInt16] = []
        var tail: [UInt16] = []
        var sawDoubleColon = false

        var i = 0
        let count = utf8.count

        // Leading "::"
        if count >= 2 && utf8[0] == UInt8(ascii: ":") && utf8[1] == UInt8(ascii: ":") {
            sawDoubleColon = true
            i = 2
            // "::" alone is the all-zero address.
            if i == count {
                return [UInt8](repeating: 0, count: 16)
            }
        } else if utf8[0] == UInt8(ascii: ":") {
            // A single leading colon (not "::") is invalid.
            return nil
        }

        func append(_ group: UInt16) {
            if sawDoubleColon {
                tail.append(group)
            } else {
                head.append(group)
            }
        }

        while i < count {
            // Try to parse an embedded IPv4 (only valid as the final element).
            if containsDot(utf8, from: i) {
                guard let v4 = parseIPv4(String(decoding: utf8[i..<count], as: UTF8.self)) else {
                    return nil
                }
                let g0 = UInt16(v4[0]) << 8 | UInt16(v4[1])
                let g1 = UInt16(v4[2]) << 8 | UInt16(v4[3])
                append(g0)
                append(g1)
                i = count
                break
            }

            // Parse a hextet: 1-4 hex digits.
            var digits = 0
            var value: UInt32 = 0
            while i < count, let h = hexValue(utf8[i]) {
                value = value << 4 | UInt32(h)
                digits += 1
                i += 1
                if digits > 4 { return nil }
            }
            guard digits > 0 else { return nil }
            append(UInt16(value))

            if i == count { break }

            // Separator handling.
            guard utf8[i] == UInt8(ascii: ":") else { return nil }
            i += 1
            if i < count && utf8[i] == UInt8(ascii: ":") {
                // Second "::" is invalid.
                if sawDoubleColon { return nil }
                sawDoubleColon = true
                i += 1
                // Trailing "::" terminates the address.
                if i == count { break }
            } else if i == count {
                // Trailing single colon (not part of "::") is invalid.
                return nil
            }
        }

        let totalGroups = head.count + tail.count
        if sawDoubleColon {
            guard totalGroups <= 7 else { return nil }
        } else {
            guard totalGroups == 8 else { return nil }
        }

        var groups = [UInt16](repeating: 0, count: 8)
        for (index, g) in head.enumerated() {
            groups[index] = g
        }
        if sawDoubleColon {
            let tailStart = 8 - tail.count
            for (index, g) in tail.enumerated() {
                groups[tailStart + index] = g
            }
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        for g in groups {
            bytes.append(UInt8(g >> 8))
            bytes.append(UInt8(g & 0xFF))
        }
        return bytes
    }

    /// Formats 16 network-order IPv6 bytes as the RFC 5952 canonical textual
    /// form (longest zero-run compressed to "::", lowercase hex, leading zeros
    /// suppressed).
    ///
    /// - Returns: The canonical textual address, or `nil` if `bytes.count != 16`.
    public static func formatIPv6(_ bytes: [UInt8]) -> String? {
        guard bytes.count == 16 else { return nil }
        var groups = [UInt16](repeating: 0, count: 8)
        for index in 0..<8 {
            groups[index] = UInt16(bytes[index * 2]) << 8 | UInt16(bytes[index * 2 + 1])
        }
        return compressIPv6(groups)
    }

    // MARK: - RFC 5952 compression

    /// Compresses 8 IPv6 groups into RFC 5952 textual form.
    ///
    /// - Replace the longest run of consecutive zero groups (min length 2) with
    ///   "::"; on ties use the first occurrence.
    /// - Suppress leading zeros in each group; lowercase hex.
    static func compressIPv6(_ groups: [UInt16]) -> String {
        // Find the longest run of consecutive zero groups.
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0

        for i in 0..<8 {
            if groups[i] == 0 {
                if curStart == -1 { curStart = i }
                curLen += 1
                if curLen > bestLen {
                    bestStart = curStart
                    bestLen = curLen
                }
            } else {
                curStart = -1
                curLen = 0
            }
        }

        // Only compress runs of 2 or more zeros (RFC 5952 §4.2.3).
        if bestLen < 2 {
            bestStart = -1
            bestLen = 0
        }

        var parts: [String] = []
        var i = 0
        while i < 8 {
            if i == bestStart {
                if i == 0 { parts.append("") }
                parts.append("")
                i += bestLen
                if i == 8 { parts.append("") }
            } else {
                parts.append(hexString(groups[i]))
                i += 1
            }
        }

        return joined(parts, separator: ":")
    }

    // MARK: - Foundation-free text helpers

    @inline(__always)
    static func decimalValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return byte - UInt8(ascii: "0")
        default:
            return nil
        }
    }

    @inline(__always)
    static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return byte - UInt8(ascii: "A") + 10
        default:
            return nil
        }
    }

    /// Whether a "." appears in `utf8[from...]` before the next ":".
    @inline(__always)
    static func containsDot(_ utf8: [UInt8], from: Int) -> Bool {
        var i = from
        while i < utf8.count {
            if utf8[i] == UInt8(ascii: ".") { return true }
            if utf8[i] == UInt8(ascii: ":") { return false }
            i += 1
        }
        return false
    }

    /// Lowercase hex string of a 16-bit group with leading zeros suppressed.
    @inline(__always)
    static func hexString(_ value: UInt16) -> String {
        if value == 0 { return "0" }
        let digits: [Character] = ["0", "1", "2", "3", "4", "5", "6", "7",
                                   "8", "9", "a", "b", "c", "d", "e", "f"]
        var chars: [Character] = []
        var v = value
        while v > 0 {
            chars.append(digits[Int(v & 0xF)])
            v >>= 4
        }
        return String(chars.reversed())
    }

    /// Joins string parts with a separator (Foundation-free).
    @inline(__always)
    static func joined(_ parts: [String], separator: String) -> String {
        var result = ""
        for (index, part) in parts.enumerated() {
            if index > 0 { result.append(separator) }
            result.append(part)
        }
        return result
    }
}
