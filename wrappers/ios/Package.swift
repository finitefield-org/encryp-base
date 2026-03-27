// swift-tools-version: 6.0

import Foundation
import PackageDescription

let manifestURL = URL(fileURLWithPath: #filePath)
let packageRoot = manifestURL.deletingLastPathComponent()
let repoRoot = packageRoot.deletingLastPathComponent().deletingLastPathComponent()

let buildDir = repoRoot.appendingPathComponent("build").path
let homebrewLibDir = "/opt/homebrew/lib"
let localLibDir = "/usr/local/lib"

let package = Package(
    name: "EncSQLiteIOS",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "EncSQLite",
            targets: ["EncSQLite"]
        ),
    ],
    targets: [
        .target(
            name: "CEncSQLite",
            path: "Sources/CEncSQLite",
            publicHeadersPath: "include",
            linkerSettings: [
                .unsafeFlags(["-L", buildDir]),
                .unsafeFlags(["-L", homebrewLibDir]),
                .unsafeFlags(["-L", localLibDir]),
                .linkedLibrary("encsqlite_base"),
                .linkedLibrary("sqlite3_vendor"),
                .linkedLibrary("ssl"),
                .linkedLibrary("crypto"),
                .linkedLibrary("sodium"),
                .linkedLibrary("argon2"),
            ]
        ),
        .target(
            name: "EncSQLite",
            dependencies: ["CEncSQLite"],
            path: "Sources/EncSQLite",
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "EncSQLiteTests",
            dependencies: ["EncSQLite", "CEncSQLite"],
            path: "Tests/EncSQLiteTests"
        ),
    ]
)
