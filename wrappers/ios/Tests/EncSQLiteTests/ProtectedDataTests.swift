import XCTest

@testable import EncSQLite

final class EncSQLiteProtectedDataTests: XCTestCase {
    func testProtectedDataHelperIsConditionalAndAvailableOnIOS() throws {
#if canImport(UIKit)
        let available = EncSQLiteProtectedDataState.waitUntilAvailable(timeout: 0.01)
        XCTAssertEqual(available, EncSQLiteProtectedDataState.isAvailable)
#else
        throw XCTSkip("requires UIKit / iOS runtime")
#endif
    }
}
