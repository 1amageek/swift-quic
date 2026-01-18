/// Stream Scheduler
///
/// Priority-based stream scheduler with fair queuing within priority levels.

import Foundation

/// Priority-based stream scheduler with fair queuing
///
/// This scheduler orders streams by their priority (urgency level) and implements
/// round-robin scheduling within each priority group to ensure fairness.
///
/// ## Scheduling Algorithm
/// 1. Group streams by urgency level (0-7)
/// 2. Process groups in priority order (0 first, 7 last)
/// 3. Within each group, use round-robin starting from cursor position
/// 4. Cursors persist between calls for fairness
///
/// ## Thread Safety
/// This struct is not thread-safe by itself. It should be used within a synchronized context.
struct StreamScheduler: Sendable {
    /// Round-robin cursors per urgency level
    ///
    /// Key: urgency level (0-7)
    /// Value: cursor position for next scheduling round
    private var cursors: [UInt8: Int] = [:]

    /// Creates a new StreamScheduler
    init() {}

    /// Schedules streams and returns them in priority order
    ///
    /// - Parameter streams: Dictionary of stream ID to DataStream
    /// - Returns: Array of (streamID, stream) tuples ordered by priority with fair queuing
    mutating func scheduleStreams(
        _ streams: [UInt64: DataStream]
    ) -> [(streamID: UInt64, stream: DataStream)] {
        // Group streams by urgency
        var groups: [UInt8: [(UInt64, DataStream)]] = [:]
        for (streamID, stream) in streams {
            let urgency = stream.priority.urgency
            groups[urgency, default: []].append((streamID, stream))
        }

        // Sort each group by stream ID for deterministic ordering
        for (urgency, group) in groups {
            groups[urgency] = group.sorted { $0.0 < $1.0 }
        }

        // Build result in priority order with round-robin
        var result: [(streamID: UInt64, stream: DataStream)] = []

        // Process urgency levels in order (0 = highest priority first)
        for urgency in UInt8(0)...7 {
            guard let group = groups[urgency], !group.isEmpty else {
                continue
            }

            // Get cursor for this urgency level
            let cursor = cursors[urgency] ?? 0
            let validCursor = cursor % group.count

            // Rotate the group to start from cursor position
            let rotated = rotateArray(group, startingAt: validCursor)
            result.append(contentsOf: rotated)

            // Update cursor for next round (advance by group size)
            cursors[urgency] = (validCursor + group.count) % group.count
        }

        return result
    }

    /// Advances the cursor for a specific urgency level
    ///
    /// Call this after a stream at the given urgency has sent data.
    /// This ensures the next stream in the group gets priority next time.
    mutating func advanceCursor(for urgency: UInt8, groupSize: Int) {
        guard groupSize > 0 else { return }
        let current = cursors[urgency] ?? 0
        cursors[urgency] = (current + 1) % groupSize
    }

    /// Resets all cursors
    ///
    /// Call this when streams are significantly added/removed.
    mutating func resetCursors() {
        cursors.removeAll()
    }

    /// Removes cursor for a specific urgency level
    mutating func removeCursor(for urgency: UInt8) {
        cursors.removeValue(forKey: urgency)
    }

    // MARK: - Private

    /// Rotates an array to start at a specific index
    private func rotateArray<T>(_ array: [T], startingAt index: Int) -> [T] {
        guard !array.isEmpty, index > 0, index < array.count else {
            return array
        }
        return Array(array[index...]) + Array(array[..<index])
    }
}

// MARK: - StreamScheduler Statistics

extension StreamScheduler {
    /// Returns the current cursor positions for debugging
    var cursorPositions: [UInt8: Int] {
        cursors
    }
}
