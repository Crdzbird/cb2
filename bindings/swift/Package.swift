// swift-tools-version: 6.0

import Foundation
import PackageDescription

let xcframework = "Cb2C.xcframework"
let useXCFramework =
    Context.environment["CB2_SWIFT_SYSTEM_LIBRARY"] == nil
    && FileManager.default.fileExists(atPath: "\(Context.packageDirectory)/\(xcframework)")

let native: Target =
    useXCFramework
    ? .binaryTarget(name: "CCb2", path: xcframework)
    : .systemLibrary(name: "CCb2", path: "Sources/CCb2")

let package = Package(
    name: "Cb2",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "Cb2", targets: ["Cb2"])
    ],
    targets: [
        native,
        .target(name: "Cb2", dependencies: ["CCb2"]),
        .testTarget(name: "Cb2Tests", dependencies: ["Cb2"]),
    ]
)
