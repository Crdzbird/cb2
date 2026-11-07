// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Cb2Benchmarks",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(name: "Cb2", path: ".."),
        .package(url: "https://github.com/ordo-one/package-benchmark", exact: "1.37.0"),
        .package(url: "https://github.com/vapor/jwt-kit", exact: "5.7.1"),
        .package(
            url: "https://github.com/aidantwoods/swift-paseto", revision: "811e2589a7eb65c16a39e64841034e11daa803a2"),
    ],
    targets: [
        .target(
            name: "TokenFixtures",
            dependencies: [
                .product(name: "Cb2", package: "Cb2"),
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Paseto", package: "swift-paseto"),
            ]
        ),
        .executableTarget(name: "token-sizes", dependencies: ["TokenFixtures"]),
        .executableTarget(
            name: "TokenBenchmarks",
            dependencies: [
                "TokenFixtures",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/TokenBenchmarks",
            plugins: [.plugin(name: "BenchmarkPlugin", package: "package-benchmark")]
        ),
    ]
)
