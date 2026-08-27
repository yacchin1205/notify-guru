import XCTest

final class DeviceGroupFlowUITests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testAddToGroupRequestIsVisibleAndDiscardedAfterRelaunch() {
        let app = XCUIApplication()
        app.launch()

        let eraseSavedData = app.buttons["Erase saved data"]
        if eraseSavedData.waitForExistence(timeout: 5) {
            XCTAssertTrue(app.staticTexts["Unable to start"].exists)
            attachScreenshot(named: "00-startup-error", app: app)
            eraseSavedData.tap()
        }

        let manageGroup = app.buttons["Manage group"]
        XCTAssertTrue(manageGroup.waitForExistence(timeout: 20))
        attachScreenshot(named: "01-initial", app: app)
        manageGroup.tap()

        let addToGroup = app.buttons["Add this device to another group"]
        XCTAssertTrue(addToGroup.waitForExistence(timeout: 5))
        attachScreenshot(named: "02-device-group-management", app: app)
        addToGroup.tap()

        let removeAndContinue = app.buttons["Remove and continue"]
        if removeAndContinue.waitForExistence(timeout: 2) {
            removeAndContinue.tap()
        }

        let invitationQRCode = app.images["QR code for adding this device to a group"]
        XCTAssertTrue(invitationQRCode.waitForExistence(timeout: 20))
        XCTAssertTrue(app.buttons["Share link"].exists)
        XCTAssertFalse(addToGroup.exists)
        attachScreenshot(named: "03-waiting-for-group", app: app)

        app.terminate()
        app.launch()

        XCTAssertTrue(manageGroup.waitForExistence(timeout: 20))
        XCTAssertFalse(invitationQRCode.exists)
        attachScreenshot(named: "04-after-relaunch", app: app)

        manageGroup.tap()
        XCTAssertTrue(addToGroup.waitForExistence(timeout: 5))
        XCTAssertFalse(invitationQRCode.exists)
        attachScreenshot(named: "05-management-after-relaunch", app: app)
    }

    private func attachScreenshot(named name: String, app: XCUIApplication) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
