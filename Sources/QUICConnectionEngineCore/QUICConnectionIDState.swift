import QUICWire

struct QUICConnectionIDRecord: Sendable, Equatable {
    var sequenceNumber: UInt64
    var connectionID: ConnectionID
    var statelessResetToken: [UInt8]?
    var isRetired: Bool
}

/// Bounded connection-ID storage for one direction of a QUIC connection.
///
/// QUIC transport parameters cap the active set, so contiguous storage avoids
/// hashing allocations without allowing an attacker to grow an unbounded map.
struct QUICConnectionIDState: Sendable {
    private(set) var records: [QUICConnectionIDRecord]
    private(set) var retirePriorTo: UInt64

    init(
        initialConnectionID: ConnectionID,
        statelessResetToken: [UInt8]? = nil
    ) {
        self.records = [QUICConnectionIDRecord(
            sequenceNumber: 0,
            connectionID: initialConnectionID,
            statelessResetToken: statelessResetToken,
            isRetired: false
        )]
        self.retirePriorTo = 0
    }

    var largestIssuedSequenceNumber: UInt64 {
        records.last?.sequenceNumber ?? 0
    }

    var activeCount: Int {
        var count = 0
        for record in records where !record.isRetired && record.sequenceNumber >= retirePriorTo {
            count += 1
        }
        return count
    }

    var activeRecords: [QUICConnectionIDRecord] {
        records.filter { !$0.isRetired && $0.sequenceNumber >= retirePriorTo }
    }

    func record(sequenceNumber: UInt64) -> QUICConnectionIDRecord? {
        records.first { $0.sequenceNumber == sequenceNumber }
    }

    func containsActive(_ connectionID: ConnectionID) -> Bool {
        records.contains {
            !$0.isRetired
                && $0.sequenceNumber >= retirePriorTo
                && $0.connectionID == connectionID
        }
    }

    mutating func replaceInitialConnectionID(
        _ connectionID: ConnectionID,
        statelessResetToken: [UInt8]? = nil
    ) {
        guard let index = records.firstIndex(where: { $0.sequenceNumber == 0 }) else {
            records.insert(QUICConnectionIDRecord(
                sequenceNumber: 0,
                connectionID: connectionID,
                statelessResetToken: statelessResetToken,
                isRetired: false
            ), at: 0)
            return
        }
        records[index].connectionID = connectionID
        if let statelessResetToken {
            records[index].statelessResetToken = statelessResetToken
        }
    }

    mutating func setInitialStatelessResetToken(_ token: [UInt8]) {
        guard let index = records.firstIndex(where: { $0.sequenceNumber == 0 }) else { return }
        records[index].statelessResetToken = token
    }

    /// Inserts a new record and returns the sequence numbers newly covered by
    /// `retire_prior_to`. A duplicate is idempotent only when both the CID and
    /// reset token are byte-for-byte identical.
    mutating func receive(
        _ frame: NewConnectionIDFrame,
        activeLimit: UInt64
    ) throws(QUICEngineError) -> [UInt64] {
        guard !frame.connectionID.isEmpty else {
            throw .protocolViolation("NEW_CONNECTION_ID contains a zero-length connection ID")
        }

        if let existing = record(sequenceNumber: frame.sequenceNumber) {
            guard existing.connectionID == frame.connectionID,
                  existing.statelessResetToken == frame.statelessResetToken else {
                throw .protocolViolation("NEW_CONNECTION_ID reuses a sequence number with different values")
            }
        } else {
            guard !records.contains(where: {
                $0.connectionID == frame.connectionID
                    || $0.statelessResetToken == frame.statelessResetToken
            }) else {
                throw .protocolViolation("NEW_CONNECTION_ID reuses a connection ID or stateless reset token")
            }
            records.append(QUICConnectionIDRecord(
                sequenceNumber: frame.sequenceNumber,
                connectionID: frame.connectionID,
                statelessResetToken: frame.statelessResetToken,
                isRetired: false
            ))
            records.sort { $0.sequenceNumber < $1.sequenceNumber }
        }

        let previousRetirePriorTo = retirePriorTo
        retirePriorTo = max(retirePriorTo, frame.retirePriorTo)
        var newlyRetired: [UInt64] = []
        if retirePriorTo > previousRetirePriorTo {
            for index in records.indices where records[index].sequenceNumber < retirePriorTo {
                if !records[index].isRetired {
                    records[index].isRetired = true
                    newlyRetired.append(records[index].sequenceNumber)
                }
            }
        }

        guard UInt64(activeCount) <= activeLimit else {
            throw .protocolViolation("peer exceeded active_connection_id_limit")
        }
        return newlyRetired
    }

    mutating func issue(
        sequenceNumber: UInt64,
        connectionID: ConnectionID,
        statelessResetToken: [UInt8]
    ) throws(QUICEngineError) {
        guard !connectionID.isEmpty else {
            throw .invalidState("a locally issued connection ID must not be empty")
        }
        guard sequenceNumber > largestIssuedSequenceNumber else {
            throw .invalidState("local connection ID sequence numbers must increase")
        }
        guard !records.contains(where: {
            $0.connectionID == connectionID
                || $0.statelessResetToken == statelessResetToken
        }) else {
            throw .invalidState("a local connection ID or stateless reset token was reused")
        }
        records.append(QUICConnectionIDRecord(
            sequenceNumber: sequenceNumber,
            connectionID: connectionID,
            statelessResetToken: statelessResetToken,
            isRetired: false
        ))
    }

    mutating func retire(sequenceNumber: UInt64) -> QUICConnectionIDRecord? {
        guard let index = records.firstIndex(where: { $0.sequenceNumber == sequenceNumber }) else {
            return nil
        }
        records[index].isRetired = true
        return records[index]
    }

    func firstActive() -> QUICConnectionIDRecord? {
        records.first { !$0.isRetired && $0.sequenceNumber >= retirePriorTo }
    }

    func matchesActiveResetToken(packet: Span<UInt8>) -> Bool {
        let tokenLength = ProtocolLimits.statelessResetTokenLength
        guard packet.count >= tokenLength else { return false }
        let candidate = packet.extracting((packet.count - tokenLength)..<packet.count)
        for record in records where !record.isRetired {
            guard let token = record.statelessResetToken, token.count == tokenLength else { continue }
            var difference: UInt8 = 0
            for index in 0..<tokenLength {
                difference |= candidate[index] ^ token[index]
            }
            if difference == 0 { return true }
        }
        return false
    }
}
