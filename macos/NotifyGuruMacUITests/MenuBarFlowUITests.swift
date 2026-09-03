import AppKit
import XCTest

final class MenuBarFlowUITests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testRecoverableStartupFailureShowsWarningAndCanReset() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-recoverable-startup-error"]
        app.launch()

        let warningItem = app.menuBars.statusItems["notify.guru, sync error"]
        XCTAssertTrue(warningItem.waitForExistence(timeout: 5))
        attachScreenshot(named: "40-sync-error-menu-bar-warning", app: app)
        warningItem.click()

        XCTAssertTrue(app.staticTexts["Unable to start"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["The saved notify.guru data on this device can no longer be opened."].exists)
        let erase = app.buttons["Erase Saved Data"]
        XCTAssertTrue(erase.isHittable)
        XCTAssertFalse(app.buttons["Add Session"].isEnabled)
        XCTAssertFalse(app.buttons["Device Group"].isEnabled)
        attachScreenshot(named: "41-recoverable-startup-error", app: app)

        erase.click()
        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        attachScreenshot(named: "42-recovered-after-erasing-data", app: app)
        XCTAssertTrue(app.menuBars.statusItems["notify.guru, 3 unresolved items"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Unable to start"].exists)
    }

    func testNotificationHistoryAndRequestDismissalFromMenuBar() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, 3 unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        attachScreenshot(named: "00-menu-bar-count", app: app)
        statusItem.click()

        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["First accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["Continue the meeting?"].exists)
        XCTAssertTrue(app.staticTexts["3 unresolved items"].exists)
        attachScreenshot(named: "01-menu-bar-session", app: app)
        XCTAssertTrue(app.staticTexts["20m ago"].exists)

        app.buttons.matching(identifier: "Dismiss Notification").element(boundBy: 0).click()
        XCTAssertFalse(app.staticTexts["First accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["2 unresolved items"].exists)
        XCTAssertTrue(app.menuBars.statusItems["notify.guru, 2 unresolved items"].waitForExistence(timeout: 5))
        attachScreenshot(named: "02-notification-dismissed", app: app)

        app.buttons["Dismiss Request"].click()
        XCTAssertFalse(app.staticTexts["Continue the meeting?"].exists)
        XCTAssertTrue(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["1 unresolved item"].exists)
        XCTAssertTrue(app.menuBars.statusItems["notify.guru, 1 unresolved item"].waitForExistence(timeout: 5))
        attachScreenshot(named: "03-request-dismissed", app: app)

        app.buttons["Dismiss Notification"].click()
        XCTAssertFalse(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertFalse(app.staticTexts["1 unresolved item"].exists)
        XCTAssertTrue(app.menuBars.statusItems["notify.guru, no unresolved items"].waitForExistence(timeout: 5))
        attachScreenshot(named: "04-all-cleared", app: app)
    }

    func testV4MessageAcceptsClipboardImage() {
        let fixture = NSImage(size: NSSize(width: 320, height: 180))
        fixture.lockFocus()
        NSColor.systemBlue.setFill()
        NSBezierPath(rect: NSRect(x: 0, y: 0, width: 320, height: 180)).fill()
        NSColor.white.setFill()
        NSBezierPath(ovalIn: NSRect(x: 120, y: 50, width: 80, height: 80)).fill()
        fixture.unlockFocus()
        NSPasteboard.general.clearContents()
        XCTAssertTrue(NSPasteboard.general.writeObjects([fixture]))

        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-photo-message"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, no unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        statusItem.click()
        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        let compose = app.buttons["Send a Message"]
        XCTAssertTrue(compose.isHittable)
        compose.click()

        let message = app.textFields["mac-message-editor"]
        let send = app.buttons["Send"]
        XCTAssertTrue(message.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Paste Image"].exists)
        XCTAssertFalse(send.isEnabled)
        attachScreenshot(named: "30-message-empty-with-paste-image", app: app)

        message.click()
        app.typeKey("v", modifierFlags: .command)
        let preview = app.images["mac-selected-photo-preview"]
        XCTAssertTrue(preview.waitForExistence(timeout: 10))
        XCTAssertTrue(send.isEnabled)
        XCTAssertTrue(app.buttons["Remove Image"].exists)
        attachScreenshot(named: "31-clipboard-image-ready", app: app)

        app.buttons["Remove Image"].click()
        XCTAssertEqual(XCTWaiter().wait(for: [absence(of: preview)], timeout: 5), .completed)
        XCTAssertFalse(send.isEnabled)

        app.buttons["Paste Image"].click()
        XCTAssertTrue(preview.waitForExistence(timeout: 10))
        XCTAssertTrue(send.isEnabled)
        attachScreenshot(named: "32-paste-button-image-ready", app: app)

        app.buttons["Remove Image"].click()
        XCTAssertEqual(XCTWaiter().wait(for: [absence(of: preview)], timeout: 5), .completed)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString("ordinary text paste", forType: .string)
        message.click()
        app.typeKey("v", modifierFlags: .command)
        XCTAssertEqual(message.value as? String, "ordinary text paste")

        app.buttons["Cancel"].click()
        XCTAssertTrue(app.buttons["Send a Message"].waitForExistence(timeout: 5))
        attachScreenshot(named: "33-image-composer-cancelled", app: app)
    }

    func testSessionSyncErrorStaysOnTheCard() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-session-sync-error"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, 3 unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        statusItem.click()
        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Invalid server response: object fields do not match the protocol"].exists)
        XCTAssertFalse(app.staticTexts["error-message"].exists)
        attachScreenshot(named: "07-session-sync-error-on-card", app: app)
    }

    func testContextMenuAndLongPressToggleStatusAttention() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, 3 unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        statusItem.click()
        let title = app.staticTexts["UI improvement test"]
        let watching = app.images["Watching Status Updates"]
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        XCTAssertFalse(watching.exists)

        title.rightClick()
        let watch = app.menuItems["Watch Status Updates"]
        XCTAssertTrue(watch.waitForExistence(timeout: 5))
        watch.click()
        XCTAssertTrue(watching.waitForExistence(timeout: 5))
        attachScreenshot(named: "05-attention-on", app: app)

        title.press(forDuration: 1)
        let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: watching)
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: 5), .completed)
        attachScreenshot(named: "06-attention-off", app: app)
    }

    func testDismissErrorKeepsRequestVisible() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-dismiss-error"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, 3 unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        statusItem.click()

        XCTAssertTrue(app.staticTexts["Continue the meeting?"].waitForExistence(timeout: 5))
        app.buttons["Dismiss Request"].click()

        XCTAssertTrue(app.staticTexts["Continue the meeting?"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["error-message"].exists)
        XCTAssertTrue(app.staticTexts["3 unresolved items"].exists)
        attachScreenshot(named: "05-dismiss-error-keeps-request", app: app)
    }

    func testManagementWindowsOpenFromMenuBar() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, 3 unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        statusItem.click()

        app.buttons["Add Session"].click()
        XCTAssertTrue(app.staticTexts["Add Session"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Paste the one-shot link shown by notifyg."].exists)
        XCTAssertTrue(app.textFields.firstMatch.exists)
        attachScreenshot(named: "05-add-session-window", app: app)

        app.typeKey("w", modifierFlags: .command)
        let deviceGroupButton = app.buttons["Device Group"]
        if !deviceGroupButton.exists {
            statusItem.click()
        }
        XCTAssertTrue(deviceGroupButton.waitForExistence(timeout: 5))
        deviceGroupButton.click()
        XCTAssertTrue(app.staticTexts["Device Group"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["ADD THIS MAC TO ANOTHER GROUP"].exists)
        XCTAssertTrue(app.staticTexts["GROUP DEVICES"].exists)
        XCTAssertTrue(app.staticTexts["This Mac"].exists)
        attachScreenshot(named: "06-device-group-window", app: app)
    }

    func testSessionsWidgetLinkOpensSessionsWindow() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        XCTAssertTrue(app.menuBars.statusItems["notify.guru, 3 unresolved items"].waitForExistence(timeout: 5))
        XCTAssertTrue(NSWorkspace.shared.open(try XCTUnwrap(URL(string: "notifyguru://sessions"))))

        XCTAssertTrue(app.windows["Sessions"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.windows["Sessions"].staticTexts["UI improvement test"].exists)
        XCTAssertTrue(app.windows["Sessions"].staticTexts["Continue the meeting?"].exists)
        attachScreenshot(named: "07-widget-link-sessions-window", app: app)
    }

    func testDeviceAdditionRequiresConfirmationAndCanBeCancelled() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-device-addition-approval"]
        app.launch()

        XCTAssertTrue(app.staticTexts["Add a Device?"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["The new device will receive notifications and can respond as a member of this device group."].exists)
        XCTAssertTrue(app.buttons["Add Device"].exists)
        attachScreenshot(named: "20-device-addition-confirmation", app: app)

        app.buttons["Cancel"].click()
        XCTAssertFalse(app.staticTexts["Add a Device?"].exists)
        attachScreenshot(named: "21-device-addition-cancelled", app: app)
    }

    func testDeviceAdditionFailureStaysVisible() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-device-addition-approval", "-ui-test-device-addition-error"]
        app.launch()

        XCTAssertTrue(app.buttons["Add Device"].waitForExistence(timeout: 5))
        app.buttons["Add Device"].click()

        XCTAssertTrue(app.staticTexts["device-addition-error"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Add a Device?"].exists)
        attachScreenshot(named: "22-device-addition-error", app: app)
    }

    func testDeviceAdditionConfirmationCanProceed() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-device-addition-approval"]
        app.launch()

        XCTAssertTrue(app.buttons["Add Device"].waitForExistence(timeout: 5))
        app.buttons["Add Device"].click()

        XCTAssertFalse(app.staticTexts["Add a Device?"].waitForExistence(timeout: 2))
        attachScreenshot(named: "23-device-addition-approved", app: app)
    }

    func testSessionLinkDoesNotRequestDeviceAdditionApproval() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-link"]
        app.launch()

        let statusItem = app.menuBars.statusItems["notify.guru, 3 unresolved items"]
        XCTAssertTrue(statusItem.waitForExistence(timeout: 5))
        statusItem.click()
        app.buttons["Add Session"].click()

        let linkField = app.textFields.firstMatch
        XCTAssertTrue(linkField.waitForExistence(timeout: 5))
        linkField.click()
        linkField.typeText(sessionLinkFixture)
        app.buttons["Continue"].click()

        XCTAssertFalse(app.staticTexts["Add Session"].waitForExistence(timeout: 2))
        XCTAssertFalse(app.staticTexts["Add a Device?"].exists)
        attachScreenshot(named: "24-session-link-joined-without-device-approval", app: app)
    }

    private var sessionLinkFixture: String {
        let secret = String(repeating: "A", count: 43)
        let publicKey = String(repeating: "A", count: 87)
        return "https://notify.guru/join#v=3&s=ui-test-session01&p=ui-test-pairing01&t=\(secret)&a=\(secret)&k=\(publicKey)&c=aabbcc"
    }

    private func absence(of element: XCUIElement) -> XCTestExpectation {
        XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: element)
    }

    private func attachScreenshot(named name: String, app: XCUIApplication) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
