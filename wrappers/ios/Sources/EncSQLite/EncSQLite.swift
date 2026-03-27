import Foundation
import CEncSQLite

public enum EncSQLiteError: Error, CustomStringConvertible, CustomDebugStringConvertible {
    case invalidFileURL
    case invalidKeyLength(actual: Int)
    case missingKeychainItem
    case protectedDataUnavailable
    case sqlite(code: Int32)

    public var description: String {
        switch self {
        case .invalidFileURL:
            return "EncSQLiteError.invalidFileURL"
        case .invalidKeyLength(let actual):
            return "EncSQLiteError.invalidKeyLength(actual: \(actual))"
        case .missingKeychainItem:
            return "EncSQLiteError.missingKeychainItem"
        case .protectedDataUnavailable:
            return "EncSQLiteError.protectedDataUnavailable"
        case .sqlite(let code):
            return "EncSQLiteError.sqlite(code: \(code), message: \(String(cString: sqlite3_errstr(code))))"
        }
    }

    public var debugDescription: String {
        description
    }
}

public struct EncSQLiteOpenOptions: Sendable {
    public var createIfMissing: Bool
    public var readOnly: Bool
    public var expectApplicationID: Bool
    public var applicationID: UInt32
    public var journalModeWAL: Bool
    public var fileProtection: FileProtectionType?

    public init(
        createIfMissing: Bool = true,
        readOnly: Bool = false,
        expectApplicationID: Bool = false,
        applicationID: UInt32 = 0,
        journalModeWAL: Bool = true,
        fileProtection: FileProtectionType? = .complete
    ) {
        self.createIfMissing = createIfMissing
        self.readOnly = readOnly
        self.expectApplicationID = expectApplicationID
        self.applicationID = applicationID
        self.journalModeWAL = journalModeWAL
        self.fileProtection = fileProtection
    }

    func makeCOptions() -> encsqlite_open_options {
        var options = encsqlite_open_options()
        options.create_if_missing = createIfMissing ? 1 : 0
        options.read_only = readOnly ? 1 : 0
        options.expect_application_id = expectApplicationID ? 1 : 0
        options.application_id = applicationID
        options.journal_mode_wal = journalModeWAL ? 1 : 0
        return options
    }
}

public final class EncSQLiteKeyMaterial {
    private var bytes: [UInt8]

    public init(raw32 bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw EncSQLiteError.invalidKeyLength(actual: bytes.count)
        }
        self.bytes = bytes
    }

    public convenience init(raw32 data: Data) throws {
        try self.init(raw32: Array(data))
    }

    deinit {
        zeroize()
    }

    fileprivate func withCKeyMaterial<R>(
        _ body: (UnsafePointer<encsqlite_key_material>) throws -> R
    ) throws -> R {
        try bytes.withUnsafeBytes { rawBytes in
            guard let baseAddress = rawBytes.baseAddress else {
                throw EncSQLiteError.invalidKeyLength(actual: rawBytes.count)
            }

            var material = encsqlite_key_material()
            material.type = ENCSQLITE_KEY_RAW_32
            material.data = baseAddress
            material.data_len = rawBytes.count

            return try withUnsafePointer(to: &material) { materialPointer in
                try body(materialPointer)
            }
        }
    }

    private func zeroize() {
        for index in bytes.indices {
            bytes[index] = 0
        }
    }
}

public final class EncSQLiteDatabase {
    public let fileURL: URL
    private var connection: OpaquePointer?

    private init(fileURL: URL, connection: OpaquePointer) {
        self.fileURL = fileURL
        self.connection = connection
    }

    deinit {
        closeSilently()
    }

    public var sqlite3Handle: OpaquePointer? {
        guard let connection else {
            return nil
        }
        return encsqlite_connection_sqlite3(connection)
    }

    public static func open(
        fileURL: URL,
        key: EncSQLiteKeyMaterial,
        options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
    ) throws -> EncSQLiteDatabase {
        guard fileURL.isFileURL else {
            throw EncSQLiteError.invalidFileURL
        }

        return try key.withCKeyMaterial { keyMaterial in
            var cOptions = options.makeCOptions()
            var rawConnection: OpaquePointer?
            let rc = fileURL.withUnsafeFileSystemRepresentation { fsPath -> Int32 in
                guard let fsPath else {
                    return SQLITE_MISUSE
                }
                return encsqlite_open_v2(&rawConnection, fsPath, keyMaterial, &cOptions)
            }
            guard rc == SQLITE_OK else {
                throw EncSQLiteError.sqlite(code: rc)
            }
            guard let rawConnection else {
                throw EncSQLiteError.sqlite(code: SQLITE_ERROR)
            }
            let database = EncSQLiteDatabase(fileURL: fileURL, connection: rawConnection)
            do {
                try database.ensureFileProtection(options.fileProtection, readOnly: options.readOnly)
                return database
            } catch {
                try? database.close()
                throw error
            }
        }
    }

    public static func open(
        path: String,
        key: EncSQLiteKeyMaterial,
        options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
    ) throws -> EncSQLiteDatabase {
        try open(fileURL: URL(fileURLWithPath: path), key: key, options: options)
    }

    public static func open(
        fileURL: URL,
        keychainItem: EncSQLiteKeychainItem,
        options: EncSQLiteOpenOptions = EncSQLiteOpenOptions()
    ) throws -> EncSQLiteDatabase {
        guard var storedKey = try keychainItem.load() else {
            throw EncSQLiteError.missingKeychainItem
        }
        defer {
            storedKey.resetBytes(in: storedKey.startIndex..<storedKey.endIndex)
        }
        guard storedKey.count == ENCSQLITE_CODEC_KEY_BYTES else {
            throw EncSQLiteError.invalidKeyLength(actual: storedKey.count)
        }
        return try open(fileURL: fileURL, key: try EncSQLiteKeyMaterial(raw32: storedKey), options: options)
    }

    public static func open(
        fileURL: URL,
        keychainItem: EncSQLiteKeychainItem,
        options: EncSQLiteOpenOptions = EncSQLiteOpenOptions(),
        waitForProtectedDataTimeout timeout: TimeInterval,
        protectedDataWait: ((TimeInterval) -> Bool)? = nil
    ) throws -> EncSQLiteDatabase {
        let waiter = protectedDataWait ?? EncSQLiteProtectedDataState.waitUntilAvailable
        guard waiter(timeout) else {
            throw EncSQLiteError.protectedDataUnavailable
        }
        return try open(fileURL: fileURL, keychainItem: keychainItem, options: options)
    }

    public func checkpoint(truncate: Bool = false) throws {
        guard let connection else {
            throw EncSQLiteError.sqlite(code: SQLITE_MISUSE)
        }
        let rc = encsqlite_checkpoint(connection, truncate ? 1 : 0)
        guard rc == SQLITE_OK else {
            throw EncSQLiteError.sqlite(code: rc)
        }
    }

    public func close() throws {
        guard let connection else {
            return
        }

        let rc = encsqlite_close_secure(connection)
        guard rc == SQLITE_OK else {
            throw EncSQLiteError.sqlite(code: rc)
        }
        self.connection = nil
    }

    private func closeSilently() {
        guard let connection else {
            return
        }

        if encsqlite_close_secure(connection) == SQLITE_OK {
            self.connection = nil
        }
    }

    private func ensureFileProtection(
        _ protection: FileProtectionType?,
        readOnly: Bool
    ) throws {
        guard let protection else {
            return
        }

        let fileManager = FileManager.default
        let path = fileURL.path

        if !readOnly {
            try fileManager.setAttributes([.protectionKey: protection], ofItemAtPath: path)
        }

        let attributes = try fileManager.attributesOfItem(atPath: path)
        guard let actualProtection = attributes[.protectionKey] as? FileProtectionType,
              actualProtection == protection else {
            throw EncSQLiteError.sqlite(code: SQLITE_IOERR)
        }
    }
}
