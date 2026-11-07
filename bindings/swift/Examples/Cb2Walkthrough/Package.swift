// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Cb2Walkthrough",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "Cb2Walkthrough", targets: ["Cb2Walkthrough"]),
        .executable(name: "cb2-walkthrough", targets: ["cb2-walkthrough"]),
    ],
    dependencies: [
        .package(name: "Cb2", path: "../..")
    ],
    targets: [
        .target(name: "Cb2Walkthrough", dependencies: [.product(name: "Cb2", package: "Cb2")]),
        .executableTarget(name: "cb2-walkthrough", dependencies: ["Cb2Walkthrough"]),
    ]
)
