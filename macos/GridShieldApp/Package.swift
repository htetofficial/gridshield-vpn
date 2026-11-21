// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "GridShieldApp",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "GridShieldApp", targets: ["GridShieldApp"])
    ],
    targets: [
        .executableTarget(
            name: "GridShieldApp",
            path: "Sources/GridShieldApp"
        )
    ]
)
