#if canImport(UIKit)
import Dispatch
import UIKit

public enum EncSQLiteProtectedDataState {
    public static var isAvailable: Bool {
        UIApplication.shared.isProtectedDataAvailable
    }

    public static func waitUntilAvailable(timeout: TimeInterval) -> Bool {
        if isAvailable {
            return true
        }

        let semaphore = DispatchSemaphore(value: 0)
        let token = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification,
            object: nil,
            queue: nil
        ) { _ in
            semaphore.signal()
        }

        defer {
            NotificationCenter.default.removeObserver(token)
        }

        let deadline = DispatchTime.now() + timeout
        if semaphore.wait(timeout: deadline) == .success {
            return true
        }
        return isAvailable
    }
}
#endif
