// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Cb2",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "Cb2", targets: ["Cb2"])
    ],
    targets: [
        .systemLibrary(name: "CCb2", path: "Sources/CCb2"),
        .target(name: "Cb2", dependencies: ["CCb2"]),
        .testTarget(name: "Cb2Tests", dependencies: ["Cb2"]),
    ]
)
