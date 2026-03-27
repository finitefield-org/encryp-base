import Foundation
import XCTest

import CEncSQLite
@testable import EncSQLite

final class EncSQLiteTests: XCTestCase {
    private func temporaryDatabaseURL(_ name: String) -> URL {
        let fileName = "encryp-base-ios-\(name)-\(UUID().uuidString).sqlite"
        return FileManager.default.temporaryDirectory.appendingPathComponent(fileName)
    }

    private func createPlaintextDatabase(at url: URL) throws {
        var db: OpaquePointer?
        let openRC = sqlite3_open(url.path, &db)
        XCTAssertEqual(openRC, SQLITE_OK)
        guard openRC == SQLITE_OK, let db else {
            throw EncSQLiteError.sqlite(code: openRC)
        }
        defer {
            _ = sqlite3_close(db)
        }

        let sql =
            "PRAGMA page_size=4096;"
            + "PRAGMA application_id=0x454E4353;"
            + "VACUUM;"
            + "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);"
            + "INSERT INTO t(value) VALUES ('plain');"

        let execRC = sqlite3_exec(db, sql, nil, nil, nil)
        XCTAssertEqual(execRC, SQLITE_OK)
        guard execRC == SQLITE_OK else {
            throw EncSQLiteError.sqlite(code: execRC)
        }
    }

    private func assertFileProtection(
        at url: URL,
        expected: FileProtectionType
    ) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let actual = attributes[.protectionKey] as? FileProtectionType
        XCTAssertEqual(actual, expected)
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

    private func migratePlaintextDatabase(
        sourceURL: URL,
        destinationURL: URL,
        keyBytes: [UInt8],
        options: EncSQLiteOpenOptions
    ) throws {
        var keyMaterial = encsqlite_key_material()
        var cOptions = options.makeCOptions()

        let migrateRC = keyBytes.withUnsafeBytes { rawBytes -> Int32 in
            guard let baseAddress = rawBytes.baseAddress else {
                return SQLITE_MISUSE
            }

            keyMaterial.type = ENCSQLITE_KEY_RAW_32
            keyMaterial.data = baseAddress
            keyMaterial.data_len = keyBytes.count

            return withUnsafePointer(to: &keyMaterial) { keyPtr in
                withUnsafePointer(to: &cOptions) { optionsPtr in
                    encsqlite_migrate_plaintext(
                        sourceURL.path,
                        destinationURL.path,
                        keyPtr,
                        optionsPtr
                    )
                }
            }
        }

        XCTAssertEqual(migrateRC, SQLITE_OK)
        guard migrateRC == SQLITE_OK else {
            throw EncSQLiteError.sqlite(code: migrateRC)
        }
    }

    func testOpenAndCheckpointEncryptedDatabase() throws {
        let sourceURL = temporaryDatabaseURL("source")
        let destinationURL = temporaryDatabaseURL("encrypted")
        let keyBytes = Array(repeating: UInt8(0x11), count: 32)
        let key = try EncSQLiteKeyMaterial(raw32: keyBytes)
        let options = EncSQLiteOpenOptions(expectApplicationID: true, applicationID: 0x454E4353)

        try createPlaintextDatabase(at: sourceURL)
        try migratePlaintextDatabase(
            sourceURL: sourceURL,
            destinationURL: destinationURL,
            keyBytes: keyBytes,
            options: options
        )

        let database = try EncSQLiteDatabase.open(
            fileURL: destinationURL,
            key: key,
            options: options
        )

        try assertFileProtection(at: destinationURL, expected: .complete)
        XCTAssertNotNil(database.sqlite3Handle)
        if let handle = database.sqlite3Handle {
            let count = try queryCount(from: handle)
            XCTAssertEqual(count, 1)
        }

        try database.checkpoint(truncate: false)
        try database.close()
        XCTAssertNil(database.sqlite3Handle)

        try? FileManager.default.removeItem(at: sourceURL)
        try? FileManager.default.removeItem(at: destinationURL)
    }
}
