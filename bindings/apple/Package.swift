// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AttachedMobile",
    platforms: [.iOS(.v18), .macOS(.v14)],
    products: [.library(name: "AttachedMobile", targets: ["AttachedMobile"])],
    targets: [
        .binaryTarget(name: "AttachedMobileFFI", path: "Artifacts/AttachedMobileFFI.xcframework"),
        .target(
            name: "AttachedMobile", dependencies: ["AttachedMobileFFI"],
            linkerSettings: [
                .linkedFramework("Security"), .linkedFramework("SystemConfiguration"),
                .linkedFramework("CoreFoundation"), .linkedFramework("Network"),
                .linkedLibrary("resolv"), .linkedLibrary("c++"), .linkedLibrary("iconv"),
            ]),
    ])
