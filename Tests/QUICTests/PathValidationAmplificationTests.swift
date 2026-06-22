/// PATH_CHALLENGE / PATH_RESPONSE Anti-Amplification Tests (RFC 9000 §8.2.1)
///
/// Verifies that a PATH_RESPONSE for an unvalidated path is only emitted when the
/// anti-amplification budget permits, is associated with the path it arrived on, and is
/// deferred (not dropped) when the budget is exhausted.

import Testing
import Foundation
@testable import QUICCore
@testable import QUICConnection

@Suite("RFC 9000 §8.2.1 - PATH_RESPONSE amplification budget")
struct PathValidationAmplificationTests {

    private let path = NetworkPath(localAddress: "127.0.0.1:443", remoteAddress: "10.0.0.5:5000")

    @Test("Unvalidated path: PATH_RESPONSE emitted when budget covers the frame")
    func responseEmittedWhenBudgetSufficient() {
        let manager = PathValidationManager()
        let challenge = Data(repeating: 0xAB, count: 8)

        // Budget exactly the PATH_RESPONSE frame size -> response is allowed.
        let frame = manager.handleChallenge(
            challenge,
            on: path,
            remainingAmplificationBudget: PathValidationManager.pathResponseFrameSize
        )

        guard case .pathResponse(let data)? = frame else {
            Issue.record("Expected a PATH_RESPONSE frame, got \(String(describing: frame))")
            return
        }
        #expect(data == challenge)
        // Nothing should be left pending since it was emitted now.
        #expect(manager.getPendingResponses().isEmpty)
    }

    @Test("Unvalidated path: PATH_RESPONSE deferred (not dropped) when budget exhausted")
    func responseDeferredWhenBudgetExhausted() {
        let manager = PathValidationManager()
        let challenge = Data(repeating: 0xCD, count: 8)

        // Budget below the frame size -> no response now.
        let frame = manager.handleChallenge(
            challenge,
            on: path,
            remainingAmplificationBudget: PathValidationManager.pathResponseFrameSize - 1
        )
        #expect(frame == nil, "Response must not be emitted when the budget is exhausted")

        // But it must be recorded as pending (deferred), never silently dropped.
        let pending = manager.getPendingResponsesWithPaths()
        #expect(pending.count == 1)
        #expect(pending.first?.data == challenge)
        #expect(pending.first?.path == path)
    }

    @Test("Validated path: PATH_RESPONSE emitted regardless of budget")
    func validatedPathIgnoresBudget() {
        let manager = PathValidationManager()

        // Validate the path by completing a challenge/response round trip.
        let ourChallenge = manager.startValidation(for: path)
        _ = manager.handleResponse(ourChallenge)
        #expect(manager.isValidated(path))

        // Even with zero budget, a validated path responds.
        let frame = manager.handleChallenge(
            Data(repeating: 0xEE, count: 8),
            on: path,
            remainingAmplificationBudget: 0
        )
        guard case .pathResponse? = frame else {
            Issue.record("Validated path must always respond to PATH_CHALLENGE")
            return
        }
    }

    @Test("Convenience handleChallenge always responds")
    func convenienceAlwaysResponds() {
        let manager = PathValidationManager()
        let challenge = Data(repeating: 0x11, count: 8)
        let frame = manager.handleChallenge(challenge)
        guard case .pathResponse(let data) = frame else {
            Issue.record("Expected PATH_RESPONSE")
            return
        }
        #expect(data == challenge)
    }
}
