// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "cb2_flutter",
    platforms: [
        .macOS("11.0")
    ],
    products: [
        .library(name: "cb2-flutter", targets: ["cb2_flutter"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "cb2_flutter",
            dependencies: [
                "cb2_c",
                .product(name: "FlutterFramework", package: "FlutterFramework"),
            ]
        ),
        .binaryTarget(name: "cb2_c", path: "Frameworks/cb2_c.xcframework"),
    ]
)
