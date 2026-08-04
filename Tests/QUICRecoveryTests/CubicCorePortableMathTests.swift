import Testing
@testable import QUICRecoveryCore

@Suite("CUBIC portable math")
struct CubicCorePortableMathTests {
    @Test("Portable cube root remains accurate across magnitudes")
    func cubeRootAccuracy() {
        let cases: [(input: Double, expected: Double)] = [
            (0, 0),
            (1, 1),
            (8, 2),
            (27, 3),
            (1e-12, 1e-4),
            (1e12, 1e4),
            (-125, -5),
        ]

        for testCase in cases {
            let actual = CubicCore.portableCubeRoot(testCase.input)
            let scale = max(1, Swift.abs(testCase.expected))
            #expect(Swift.abs(actual - testCase.expected) / scale < 1e-12)
        }
    }

    @Test("Portable cube root preserves non-finite values")
    func cubeRootNonFiniteValues() {
        #expect(CubicCore.portableCubeRoot(.infinity) == .infinity)
        #expect(CubicCore.portableCubeRoot(-.infinity) == -.infinity)
        #expect(CubicCore.portableCubeRoot(.nan).isNaN)
    }
}
