import Foundation
import Security

public enum EncSQLiteKeychainAccessibility {
    case whenUnlockedThisDeviceOnly
    case afterFirstUnlockThisDeviceOnly

    var secAttrValue: CFString {
        switch self {
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }
}

public enum EncSQLiteKeychainError: Error, CustomStringConvertible {
    case invalidServiceOrAccount
    case unexpectedItemType
    case status(OSStatus)

    public var description: String {
        switch self {
        case .invalidServiceOrAccount:
            return "EncSQLiteKeychainError.invalidServiceOrAccount"
        case .unexpectedItemType:
            return "EncSQLiteKeychainError.unexpectedItemType"
        case .status(let status):
            let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown"
            return "EncSQLiteKeychainError.status(code: \(status), message: \(message))"
        }
    }
}

public final class EncSQLiteKeychainItem {
    public let service: String
    public let account: String
    public let accessibility: EncSQLiteKeychainAccessibility

    public init(
        service: String,
        account: String,
        accessibility: EncSQLiteKeychainAccessibility = .whenUnlockedThisDeviceOnly
    ) throws {
        guard !service.isEmpty, !account.isEmpty else {
            throw EncSQLiteKeychainError.invalidServiceOrAccount
        }
        self.service = service
        self.account = account
        self.accessibility = accessibility
    }

    public func save(_ data: Data) throws {
        let query = baseQuery.merging([
            kSecAttrAccessible as String: accessibility.secAttrValue,
            kSecValueData as String: data,
        ], uniquingKeysWith: { _, new in new })

        var result: CFTypeRef?
        let addStatus = SecItemAdd(query as CFDictionary, &result)
        if addStatus == errSecSuccess {
            return
        }
        if addStatus != errSecDuplicateItem {
            throw EncSQLiteKeychainError.status(addStatus)
        }

        let updateStatus = SecItemUpdate(
            baseQuery as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus != errSecSuccess {
            throw EncSQLiteKeychainError.status(updateStatus)
        }
    }

    public func load() throws -> Data? {
        let query = baseQuery.merging([
            kSecReturnData as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ], uniquingKeysWith: { _, new in new })

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        if status != errSecSuccess {
            throw EncSQLiteKeychainError.status(status)
        }

        guard let data = result as? Data else {
            throw EncSQLiteKeychainError.unexpectedItemType
        }
        return data
    }

    public func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        if status == errSecItemNotFound || status == errSecSuccess {
            return
        }
        throw EncSQLiteKeychainError.status(status)
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}
