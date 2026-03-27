import Foundation
import XCTest

import CEncSQLite
@testable import EncSQLite

final class EncSQLiteKeychainTests: XCTestCase {
    private func temporaryDatabaseURL(_ name: String) -> URL {
        let fileName = "encryp-base-ios-keychain-\(name)-\(UUID().uuidString).sqlite"
        return FileManager.default.temporaryDirectory.appendingPathComponent(fileName)
    }

    private func queryCount(from handle: OpaquePointer) throws -> Int {
        var stmt: OpaquePointer?
        let prepareRC = sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM t;", -1, &stmt, nil)
        XCTAssertEqual(prepareRC, SQLITE_OK)
        guard prepareRC == SQLITE_OK, let stmt else {
            throw EncSQLiteError.sqlite(code: prepareRC)
        }
        defer {
            _ = sqlite3_finalize(stmt)
        }

        let stepRC = sqlite3_step(stmt)
        XCTAssertEqual(stepRC, SQLITE_ROW)
        guard stepRC == SQLITE_ROW else {
            throw EncSQLiteError.sqlite(code: stepRC)
        }

        return Int(sqlite3_column_int(stmt, 0))
    }

    private func createEncryptedDatabase(
        at url: URL,
        keyBytes: [UInt8],
        options: EncSQLiteOpenOptions
    ) throws {
        let key = try EncSQLiteKeyMaterial(raw32: keyBytes)
        let database = try EncSQLiteDatabase.open(
            fileURL: url,
            key: key,
            options: options
        )
        defer {
            try? database.close()
        }

        guard let handle = database.sqlite3Handle else {
            throw EncSQLiteError.sqlite(code: SQLITE_MISUSE)
        }

        let execRC = sqlite3_exec(
            handle,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);INSERT INTO t(value) VALUES ('keychain');",
            nil,
            nil,
            nil
        )
        XCTAssertEqual(execRC, SQLITE_OK)
        guard execRC == SQLITE_OK else {
            throw EncSQLiteError.sqlite(code: execRC)
        }
    }

    func testKeychainSaveLoadUpdateAndDelete() throws {
        let item = try EncSQLiteKeychainItem(
            service: "encryp-base-ios-\(UUID().uuidString)",
            account: "dek"
        )
        let initialSecret = Data((0..<32).map { UInt8($0) })
        let updatedSecret = Data((0..<32).map { UInt8(0xA0 + $0) })

        XCTAssertEqual(item.accessibility, .whenUnlockedThisDeviceOnly)

        try? item.delete()
        defer {
            try? item.delete()
        }

        try item.save(initialSecret)
        XCTAssertEqual(try item.load(), initialSecret)

        try item.save(updatedSecret)
        XCTAssertEqual(try item.load(), updatedSecret)

        try item.delete()
        XCTAssertNil(try item.load())
    }

    func testKeychainCanUseAfterFirstUnlockAccessibility() throws {
        let item = try EncSQLiteKeychainItem(
            service: "encryp-base-ios-\(UUID().uuidString)",
            account: "dek",
            accessibility: .afterFirstUnlockThisDeviceOnly
        )

        XCTAssertEqual(item.accessibility, .afterFirstUnlockThisDeviceOnly)
        try? item.delete()
        defer {
            try? item.delete()
        }

        let secret = Data((0..<32).map { _ in UInt8(0x55) })
        try item.save(secret)
        XCTAssertEqual(try item.load(), secret)
    }

    func testDatabaseCanOpenUsingKeychainStoredKey() throws {
        let databaseURL = temporaryDatabaseURL("open")
        let keyBytes = Array(repeating: UInt8(0x11), count: 32)
        let options = EncSQLiteOpenOptions(expectApplicationID: true, applicationID: 0x454E4353)
        let keychain = try EncSQLiteKeychainItem(
            service: "encryp-base-ios-\(UUID().uuidString)",
            account: "dek"
        )

        defer {
            try? keychain.delete()
            try? FileManager.default.removeItem(at: databaseURL)
        }

        try createEncryptedDatabase(at: databaseURL, keyBytes: keyBytes, options: options)
        try keychain.save(Data(keyBytes))

        let database = try EncSQLiteDatabase.open(
            fileURL: databaseURL,
            keychainItem: keychain,
            options: options
        )
        defer {
            try? database.close()
        }

        XCTAssertNotNil(database.sqlite3Handle)
        if let handle = database.sqlite3Handle {
            let count = try queryCount(from: handle)
            XCTAssertEqual(count, 1)
        }
    }

    func testDatabaseOpenFailsWithoutKeychainItem() throws {
        let databaseURL = temporaryDatabaseURL("missing-keychain")
        let options = EncSQLiteOpenOptions(expectApplicationID: true, applicationID: 0x454E4353)
        let keychain = try EncSQLiteKeychainItem(
            service: "encryp-base-ios-\(UUID().uuidString)",
            account: "dek"
        )

        defer {
            try? keychain.delete()
            try? FileManager.default.removeItem(at: databaseURL)
        }

        try createEncryptedDatabase(
            at: databaseURL,
            keyBytes: Array(repeating: UInt8(0x11), count: 32),
            options: options
        )

        XCTAssertThrowsError(
            try EncSQLiteDatabase.open(
                fileURL: databaseURL,
                keychainItem: keychain,
                options: options
            )
        ) { error in
            guard let encError = error as? EncSQLiteError else {
                XCTFail("unexpected error: \(error)")
                return
            }
            switch encError {
            case .missingKeychainItem:
                break
            default:
                XCTFail("unexpected error: \(encError)")
            }
        }
    }

    func testDatabaseOpenWaitsForProtectedDataBeforeUsingKeychainItem() throws {
        let databaseURL = temporaryDatabaseURL("protected-data")
        let keyBytes = Array(repeating: UInt8(0x22), count: 32)
        let options = EncSQLiteOpenOptions(expectApplicationID: true, applicationID: 0x454E4353)
        let keychain = try EncSQLiteKeychainItem(
            service: "encryp-base-ios-\(UUID().uuidString)",
            account: "dek"
        )

        defer {
            try? keychain.delete()
            try? FileManager.default.removeItem(at: databaseURL)
        }

        try createEncryptedDatabase(at: databaseURL, keyBytes: keyBytes, options: options)
        try keychain.save(Data(keyBytes))

        var waitInvoked = false
        let database = try EncSQLiteDatabase.open(
            fileURL: databaseURL,
            keychainItem: keychain,
            options: options,
            waitForProtectedDataTimeout: 0.5,
            protectedDataWait: { timeout in
                waitInvoked = true
                XCTAssertEqual(timeout, 0.5, accuracy: 0.0001)
                return true
            }
        )
        defer {
            try? database.close()
        }

        XCTAssertTrue(waitInvoked)
        XCTAssertNotNil(database.sqlite3Handle)
    }

    func testDatabaseOpenFailsWhenProtectedDataNeverBecomesAvailable() throws {
        let databaseURL = temporaryDatabaseURL("protected-data-failure")
        let keyBytes = Array(repeating: UInt8(0x23), count: 32)
        let options = EncSQLiteOpenOptions(expectApplicationID: true, applicationID: 0x454E4353)
        let keychain = try EncSQLiteKeychainItem(
            service: "encryp-base-ios-\(UUID().uuidString)",
            account: "dek"
        )

        defer {
            try? keychain.delete()
            try? FileManager.default.removeItem(at: databaseURL)
        }

        try createEncryptedDatabase(at: databaseURL, keyBytes: keyBytes, options: options)
        try keychain.save(Data(keyBytes))

        XCTAssertThrowsError(
            try EncSQLiteDatabase.open(
                fileURL: databaseURL,
                keychainItem: keychain,
                options: options,
                waitForProtectedDataTimeout: 0.5,
                protectedDataWait: { _ in false }
            )
        ) { error in
            guard let encError = error as? EncSQLiteError else {
                XCTFail("unexpected error: \(error)")
                return
            }
            switch encError {
            case .protectedDataUnavailable:
                break
            default:
                XCTFail("unexpected error: \(encError)")
            }
        }
    }
}
