import XCTest

final class DeviceGroupFlowUITests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testStartupScreenTransitionsToAppInLightMode() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-startup-screen", "-ui-test-session-history", "-ui-test-light-mode"]
        app.launch()

        let startupScreen = app.otherElements["startup-screen"]
        XCTAssertTrue(startupScreen.waitForExistence(timeout: 2))
        XCTAssertEqual(startupScreen.value as? String, "light")
        XCTAssertTrue(app.staticTexts["startup-title"].exists)
        XCTAssertTrue(app.descendants(matching: .any)["startup-progress"].exists)
        attachScreenshot(named: "30-startup-light", app: app)

        startupScreen.tap()
        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.otherElements["startup-screen"].exists)
        attachScreenshot(named: "31-startup-light-complete", app: app)
    }

    func testStartupScreenTransitionsToAppInDarkMode() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-startup-screen", "-ui-test-session-history", "-ui-test-dark-mode"]
        app.launch()

        let startupScreen = app.otherElements["startup-screen"]
        XCTAssertTrue(startupScreen.waitForExistence(timeout: 2))
        XCTAssertEqual(startupScreen.value as? String, "dark")
        XCTAssertTrue(app.staticTexts["startup-title"].exists)
        XCTAssertTrue(app.descendants(matching: .any)["startup-progress"].exists)
        attachScreenshot(named: "32-startup-dark", app: app)

        startupScreen.tap()
        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.otherElements["startup-screen"].exists)
        attachScreenshot(named: "33-startup-dark-complete", app: app)
    }

    func testStartupFailureReplacesStartupScreenWithError() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-startup-screen", "-ui-test-startup-error"]
        app.launch()

        XCTAssertTrue(app.otherElements["startup-screen"].waitForExistence(timeout: 2))
        attachScreenshot(named: "34-startup-before-error", app: app)

        app.otherElements["startup-screen"].tap()
        XCTAssertTrue(app.staticTexts["Unable to start"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Startup failed for UI testing"].exists)
        XCTAssertFalse(app.otherElements["startup-screen"].exists)
        attachScreenshot(named: "35-startup-error", app: app)
    }

    func testMixedSessionInheritanceShowsOnlyAuthenticatedV4Session() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-mixed-session-inheritance"]
        app.launch()

        XCTAssertTrue(app.staticTexts["Authenticated v4 session"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Connected securely"].exists)
        XCTAssertFalse(app.staticTexts["Legacy v3 session"].exists)
        XCTAssertFalse(app.staticTexts["Removed signer session"].exists)
        XCTAssertFalse(app.staticTexts["Unable to start"].exists)
        attachScreenshot(named: "36-only-continuously-attested-v4-session", app: app)
    }

    func testIPhoneKeepsSessionCardsInOneColumn() throws {
        XCUIDevice.shared.orientation = .portrait
        addTeardownBlock { XCUIDevice.shared.orientation = .portrait }

        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-ipad-layout"]
        app.launch()

        let newest = app.staticTexts["Build pipeline"]
        let middle = app.staticTexts["Security audit"]
        let oldest = app.staticTexts["UI improvement test"]
        XCTAssertTrue(newest.waitForExistence(timeout: 5))
        try XCTSkipIf(app.windows.firstMatch.frame.width >= 600, "iPhone layout requires an iPhone destination")
        XCTAssertTrue(middle.exists)
        XCTAssertTrue(oldest.exists)
        XCTAssertEqual(newest.frame.minX, middle.frame.minX, accuracy: 4)
        XCTAssertLessThan(newest.frame.minY, middle.frame.minY)

        app.swipeUp()
        XCTAssertTrue(oldest.waitForExistence(timeout: 2))
        XCTAssertEqual(middle.frame.minX, oldest.frame.minX, accuracy: 4)
        XCTAssertLessThan(middle.frame.minY, oldest.frame.minY)
        attachScreenshot(named: "40-iphone-one-column", app: app)
    }

    func testIPadUsesTwoPortraitColumnsAndThreeLandscapeColumns() throws {
        XCUIDevice.shared.orientation = .portrait
        addTeardownBlock { XCUIDevice.shared.orientation = .portrait }

        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-ipad-layout"]
        app.launch()

        let newest = app.staticTexts["Build pipeline"]
        let middle = app.staticTexts["Security audit"]
        let oldest = app.staticTexts["UI improvement test"]
        XCTAssertTrue(newest.waitForExistence(timeout: 5))
        try XCTSkipUnless(app.windows.firstMatch.frame.width >= 600, "iPad layout requires an iPad destination")
        XCTAssertTrue(middle.exists)
        XCTAssertTrue(oldest.exists)
        XCTAssertEqual(newest.frame.minY, middle.frame.minY, accuracy: 4)
        XCTAssertLessThan(newest.frame.minX, middle.frame.minX)
        XCTAssertLessThan(newest.frame.minY, oldest.frame.minY)
        attachScreenshot(named: "41-ipad-portrait-two-columns", app: app)

        app.buttons["Manage group"].tap()
        XCTAssertTrue(app.navigationBars["Device Group"].waitForExistence(timeout: 5))
        attachScreenshot(named: "42-ipad-device-group-management", app: app)
        app.buttons["Done"].tap()

        XCUIDevice.shared.orientation = .landscapeLeft
        let landscape = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in
                let frame = app.windows.firstMatch.frame
                return frame.width > frame.height
            }, object: nil
        )
        XCTAssertEqual(XCTWaiter().wait(for: [landscape], timeout: 10), .completed)
        XCTAssertEqual(newest.frame.minY, middle.frame.minY, accuracy: 4)
        XCTAssertEqual(middle.frame.minY, oldest.frame.minY, accuracy: 4)
        XCTAssertLessThan(newest.frame.minX, middle.frame.minX)
        XCTAssertLessThan(middle.frame.minX, oldest.frame.minX)
        attachScreenshot(named: "43-ipad-landscape-three-columns", screen: .main)
    }

    func testAddToGroupRequestIsVisibleAndDiscardedAfterRelaunch() throws {
        XCUIDevice.shared.orientation = .portrait
        addTeardownBlock { XCUIDevice.shared.orientation = .portrait }

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

        let invitationQRCodes = app.images.matching(identifier: "QR code for adding this device to a group")
        XCTAssertTrue(invitationQRCodes.firstMatch.waitForExistence(timeout: 20))
        let invitationQRCode = try XCTUnwrap(invitationQRCodes.allElementsBoundByIndex.last)
        let shareLinks = app.buttons.matching(identifier: "Share link")
        let shareLink = try XCTUnwrap(shareLinks.allElementsBoundByIndex.last)
        XCTAssertTrue(shareLink.exists)
        XCTAssertFalse(addToGroup.exists)
        assertSquareQRCodeFits(invitationQRCode, in: app)
        attachScreenshot(named: "03-waiting-for-group", app: app)

        if app.windows.firstMatch.frame.width >= 600 {
            XCUIDevice.shared.orientation = .landscapeLeft
            XCTAssertTrue(invitationQRCode.waitForExistence(timeout: 5))
            assertSquareQRCodeFits(invitationQRCode, in: app)
            XCTAssertTrue(shareLink.isHittable)
            attachScreenshot(named: "06-ipad-landscape-waiting-for-group", screen: .main)
            XCUIDevice.shared.orientation = .portrait
        }

        app.terminate()
        app.launch()

        XCTAssertTrue(manageGroup.waitForExistence(timeout: 20))
        XCTAssertEqual(invitationQRCodes.count, 0)
        attachScreenshot(named: "04-after-relaunch", app: app)

        manageGroup.tap()
        XCTAssertTrue(addToGroup.waitForExistence(timeout: 5))
        XCTAssertEqual(invitationQRCodes.count, 0)
        attachScreenshot(named: "05-management-after-relaunch", app: app)
    }

    func testNotificationHistoryAndRequestDismissal() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["First accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["Continue the meeting?"].exists)
        XCTAssertEqual(app.buttons.matching(identifier: "Dismiss notification").count, 2)
        XCTAssertTrue(app.buttons["Dismiss request"].exists)
        XCTAssertTrue(app.staticTexts["3 unresolved items"].exists)
        XCTAssertFalse(app.staticTexts.matching(NSPredicate(format: "label == '20m ago'")).allElementsBoundByIndex.isEmpty)
        attachScreenshot(named: "10-notification-history-and-request", app: app)

        app.buttons.matching(identifier: "Dismiss notification").element(boundBy: 0).tap()
        XCTAssertFalse(app.staticTexts["First accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertEqual(app.buttons.matching(identifier: "Dismiss notification").count, 1)
        XCTAssertTrue(app.staticTexts["2 unresolved items"].exists)
        attachScreenshot(named: "11-first-notification-dismissed", app: app)

        app.buttons["Dismiss request"].tap()
        XCTAssertFalse(app.staticTexts["Continue the meeting?"].exists)
        XCTAssertFalse(app.buttons["Yes"].exists)
        XCTAssertFalse(app.buttons["No"].exists)
        XCTAssertTrue(app.staticTexts["Second accumulated notice"].exists)
        XCTAssertTrue(app.staticTexts["1 unresolved item"].exists)
        attachScreenshot(named: "12-request-dismissed", app: app)
    }

    func testRequestRemainsVisibleWhenDismissalFails() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-dismiss-error"]
        app.launch()

        XCTAssertTrue(app.staticTexts["Continue the meeting?"].waitForExistence(timeout: 5))
        app.buttons["Dismiss request"].tap()

        XCTAssertTrue(app.staticTexts["operation-error-message"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Continue the meeting?"].exists)
        XCTAssertTrue(app.staticTexts["3 unresolved items"].exists)
        attachScreenshot(named: "13-dismiss-error-keeps-request", app: app)
    }

    func testSessionSyncErrorStaysOnTheCard() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-session-sync-error"]
        app.launch()

        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Invalid server response: object fields do not match the protocol"].exists)
        XCTAssertFalse(app.staticTexts["operation-error-message"].exists)
        XCTAssertTrue(app.buttons["Yes"].isHittable)
        attachScreenshot(named: "17-session-sync-error-on-card", app: app)
    }

    func testLongPressTogglesStatusAttention() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        let title = app.staticTexts["UI improvement test"]
        let watching = app.images["Watching status updates"]
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        XCTAssertFalse(watching.exists)
        attachScreenshot(named: "14-attention-off", app: app)

        title.press(forDuration: 1)
        XCTAssertTrue(watching.waitForExistence(timeout: 5))
        attachScreenshot(named: "15-attention-on", app: app)

        title.press(forDuration: 1)
        XCTAssertEqual(XCTWaiter().wait(for: [absence(of: watching)], timeout: 5), .completed)
        attachScreenshot(named: "16-attention-off-again", app: app)
    }

    func testV4FeedbackOffersAnOptionalPhotoAndRequiresContent() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()

        XCTAssertTrue(app.staticTexts["UI improvement test"].waitForExistence(timeout: 5))
        app.buttons["Send a message"].tap()

        let editor = app.textViews["Message"]
        let takePhoto = app.buttons["Take Photo"]
        let choosePhoto = app.buttons["Choose Photos"]
        let send = app.buttons["Send"]
        XCTAssertTrue(editor.waitForExistence(timeout: 5))
        XCTAssertTrue(takePhoto.exists)
        XCTAssertTrue(choosePhoto.exists)
        XCTAssertFalse(send.isEnabled)
        attachScreenshot(named: "50-v4-feedback-empty-with-photo-actions", app: app)

        choosePhoto.tap()
        let photoThumbnail = app.images.matching(identifier: "PXGGridLayout-Info").firstMatch
        XCTAssertTrue(photoThumbnail.waitForExistence(timeout: 20))
        attachScreenshot(named: "51-v4-feedback-photo-library", app: app)

        let onboardingClose = app.buttons.matching(
            NSPredicate(format: "label == %@ OR label == %@", "Close", "閉じる")
        ).firstMatch
        if onboardingClose.exists { onboardingClose.tap() }
        for index in 0..<3 {
            app.images.matching(identifier: "PXGGridLayout-Info").element(boundBy: index)
                .coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        }
        app.buttons["Add"].tap()
        let previews = app.descendants(matching: .any).matching(identifier: "selected-photo-preview")
        let preview = previews.firstMatch
        XCTAssertTrue(preview.waitForExistence(timeout: 10))
        XCTAssertEqual(previews.count, 3)
        XCTAssertTrue(send.isEnabled)
        XCTAssertTrue(app.buttons["Remove photo 1"].exists)
        attachScreenshot(named: "52-v4-feedback-library-photo-ready", app: app)

        previews.element(boundBy: 1).tap()
        XCTAssertTrue(app.buttons["Close"].waitForExistence(timeout: 5))
        attachScreenshot(named: "54-feedback-enlarged-photo", app: app)
        app.buttons["Close"].tap()
        app.buttons["Remove photo 2"].tap()
        XCTAssertEqual(previews.count, 2)
        attachScreenshot(named: "55-feedback-middle-photo-removed", app: app)
        app.buttons["Remove photo 2"].tap()
        app.buttons["Remove photo 1"].tap()
        XCTAssertEqual(XCTWaiter().wait(for: [absence(of: preview)], timeout: 5), .completed)
        XCTAssertFalse(send.isEnabled)

        editor.tap()
        editor.typeText("A message with an optional photo")
        XCTAssertTrue(send.isEnabled)
        attachScreenshot(named: "53-v4-feedback-message-ready", app: app)
    }

    func testPhotosShareOpensNotifyGuru() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()
        let photos = XCUIApplication(bundleIdentifier: "com.apple.mobileslideshow")
        photos.launch()
        let welcomeContinue = photos.buttons.matching(NSPredicate(format: "label == 'Continue' OR label == '続ける'")).firstMatch
        if welcomeContinue.waitForExistence(timeout: 20) { welcomeContinue.tap() }
        let backToLibrary = photos.buttons["PUOneUpBarButtonItemIdentifierDone"]
        if backToLibrary.exists { backToLibrary.tap() }
        attachScreenshot(named: "60-photos-library", app: photos)
        let thumbnails = photos.images.matching(identifier: "PXGGridLayout-Info")
        XCTAssertTrue(thumbnails.firstMatch.waitForExistence(timeout: 20))
        let select = photos.buttons.matching(NSPredicate(format: "label == 'Select' OR label == '選択'")).firstMatch
        select.tap()
        XCTAssertGreaterThanOrEqual(thumbnails.count, 3)
        for index in (thumbnails.count - 3)..<thumbnails.count {
            thumbnails.element(boundBy: index).coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        }
        attachScreenshot(named: "61-photos-three-selected", app: photos)
        let share = photos.buttons.matching(NSPredicate(format: "label == 'Share' OR label == '共有'")).firstMatch
        XCTAssertTrue(share.waitForExistence(timeout: 10))
        share.tap()
        attachScreenshot(named: "62-photos-share-sheet", app: photos)
        let service = photos.cells["notify.guru"]
        XCTAssertTrue(service.waitForExistence(timeout: 10))
        service.tap()
        XCTAssertTrue(photos.buttons["Send"].waitForExistence(timeout: 10))
        XCTAssertTrue(photos.buttons["Remove photo 3"].waitForExistence(timeout: 20))
        attachScreenshot(named: "63-notify-share-extension", app: photos)
        photos.buttons["Remove photo 2"].tap()
        XCTAssertFalse(photos.buttons["Remove photo 3"].exists)
        attachScreenshot(named: "64-notify-share-middle-removed", app: photos)
        photos.buttons["Cancel"].tap()
    }

    private func absence(of element: XCUIElement) -> XCTestExpectation {
        XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: element)
    }

    func testAppIconBadgeTracksUnresolvedItems() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history", "-ui-test-app-badge"]
        app.launch()

        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let enableNotifications = app.buttons["Enable notifications for UI test"]
        XCTAssertTrue(enableNotifications.waitForExistence(timeout: 5))
        enableNotifications.tap()
        let permissionAlert = springboard.alerts.firstMatch
        XCTAssertTrue(permissionAlert.waitForExistence(timeout: 5))
        let buttons = permissionAlert.buttons
        XCTAssertEqual(buttons.count, 2)
        buttons.element(boundBy: 1).tap()
        XCTAssertTrue(app.staticTexts["3 unresolved items"].waitForExistence(timeout: 5))
        let icon = springboard.icons["notify.guru"].firstMatch
        showHomeScreen(icon: icon)
        let badgeThree = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value MATCHES %@", "3[^0-9].*"), object: icon)
        XCTAssertEqual(XCTWaiter().wait(for: [badgeThree], timeout: 10), .completed)
        attachScreenshot(named: "14-app-icon-badge-three", screen: .main)

        icon.tap()
        XCTAssertTrue(app.staticTexts["3 unresolved items"].waitForExistence(timeout: 5))
        app.buttons.matching(identifier: "Dismiss notification").element(boundBy: 0).tap()
        XCTAssertTrue(app.staticTexts["2 unresolved items"].waitForExistence(timeout: 5))
        showHomeScreen(icon: icon)
        let badgeTwo = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value MATCHES %@", "2[^0-9].*"), object: icon)
        XCTAssertEqual(XCTWaiter().wait(for: [badgeTwo], timeout: 10), .completed)
        attachScreenshot(named: "15-app-icon-badge-two", screen: .main)

        icon.tap()
        XCTAssertTrue(app.staticTexts["2 unresolved items"].waitForExistence(timeout: 5))
        app.buttons["Dismiss request"].tap()
        app.buttons.matching(identifier: "Dismiss notification").element(boundBy: 0).tap()
        XCTAssertFalse(app.staticTexts["1 unresolved item"].waitForExistence(timeout: 2))
        showHomeScreen(icon: icon)
        let badgeCleared = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == ''"), object: icon)
        XCTAssertEqual(XCTWaiter().wait(for: [badgeCleared], timeout: 10), .completed)
        attachScreenshot(named: "16-app-icon-badge-cleared", screen: .main)
    }

    func testDeviceAdditionRequiresConfirmationAndCanBeCancelled() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-device-addition-approval"]
        app.launch()

        XCTAssertTrue(app.staticTexts["Add a device to this group?"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["The new device will receive notifications and can respond as a member of this device group."].exists)
        XCTAssertTrue(app.buttons["Add device"].exists)
        attachScreenshot(named: "20-device-addition-confirmation", app: app)

        let cancel = app.buttons["Cancel"]
        if cancel.exists {
            cancel.tap()
        } else {
            // iOS 26 presents a confirmation dialog's cancel role as an
            // outside-tap dismissal instead of an accessibility button.
            app.coordinate(withNormalizedOffset: CGVector(dx: 0.05, dy: 0.2)).tap()
        }
        XCTAssertEqual(
            XCTWaiter().wait(for: [absence(of: app.staticTexts["Add a device to this group?"])], timeout: 5),
            .completed
        )
        attachScreenshot(named: "21-device-addition-cancelled", app: app)
    }

    func testDeviceAdditionFailureIsNotTreatedAsSuccess() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-device-addition-approval", "-ui-test-device-addition-error"]
        app.launch()

        XCTAssertTrue(app.buttons["Add device"].waitForExistence(timeout: 5))
        app.buttons["Add device"].tap()

        let errorMessage = app.staticTexts["operation-error-message"]
        XCTAssertTrue(errorMessage.waitForExistence(timeout: 5))
        XCTAssertTrue(errorMessage.label.contains("Device addition failed for UI testing"))
        attachScreenshot(named: "22-device-addition-error", app: app)
    }

    func testDeviceAdditionConfirmationCanProceed() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-device-addition-approval"]
        app.launch()

        XCTAssertTrue(app.buttons["Add device"].waitForExistence(timeout: 5))
        app.buttons["Add device"].tap()

        XCTAssertFalse(app.staticTexts["Add a device to this group?"].waitForExistence(timeout: 2))
        XCTAssertFalse(app.staticTexts["operation-error-message"].exists)
        attachScreenshot(named: "23-device-addition-approved", app: app)
    }

    func testSessionLinkDoesNotRequestDeviceAdditionApproval() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-link"]
        app.launch()

        XCTAssertTrue(app.buttons["Scan QR code"].firstMatch.waitForExistence(timeout: 5))
        app.buttons["Scan QR code"].firstMatch.tap()

        let linkField = app.textFields.firstMatch
        XCTAssertTrue(linkField.waitForExistence(timeout: 5))
        linkField.tap()
        linkField.typeText(sessionLinkFixture)
        app.buttons["Continue"].tap()

        XCTAssertFalse(app.navigationBars["Scan QR code"].waitForExistence(timeout: 2))
        XCTAssertFalse(app.staticTexts["Add a device to this group?"].exists)
        XCTAssertFalse(app.staticTexts["operation-error-message"].exists)
        attachScreenshot(named: "24-session-link-joined-without-device-approval", app: app)
    }

    func testInvalidJoinErrorIsVisibleInsideSheetAndRemainsUntilDismissed() {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-test-session-history"]
        app.launch()
        let scan = app.buttons["Scan QR code"].firstMatch
        XCTAssertTrue(scan.waitForExistence(timeout: 5))
        scan.tap()
        let field = app.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("not-a-pairing-link")
        app.buttons["Continue"].tap()
        let errorMessage = app.staticTexts["operation-error-message"].firstMatch
        XCTAssertTrue(errorMessage.waitForExistence(timeout: 5))
        XCTAssertTrue(errorMessage.label.contains("expected an https://notify.guru/join URL"))
        attachScreenshot(named: "40-join-error-inside-sheet", app: app)

        app.buttons["Cancel"].tap()
        XCTAssertTrue(errorMessage.waitForExistence(timeout: 5))
        attachScreenshot(named: "41-join-error-after-sheet-close", app: app)
        app.buttons["Dismiss error"].tap()
        XCTAssertFalse(errorMessage.exists)
        attachScreenshot(named: "42-join-error-acknowledged", app: app)
    }

    private var sessionLinkFixture: String {
        let secret = String(repeating: "A", count: 43)
        let publicKey = "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
        return "https://notify.guru/join#v=4&s=ui-test-session01&p=ui-test-pairing01&t=\(secret)&a=\(secret)&k=\(publicKey)&c=aabbcc"
    }

    private func attachScreenshot(named name: String, app: XCUIApplication) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func attachScreenshot(named name: String, screen: XCUIScreen) {
        let attachment = XCTAttachment(screenshot: screen.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func showHomeScreen(icon: XCUIElement) {
        XCUIDevice.shared.press(.home)
        if !icon.waitForExistence(timeout: 2) {
            XCUIDevice.shared.press(.home)
        }
        XCTAssertTrue(icon.waitForExistence(timeout: 5))
    }

    private func assertSquareQRCodeFits(_ qrCode: XCUIElement, in app: XCUIApplication) {
        let qrFrame = qrCode.frame
        let windowFrame = app.windows.firstMatch.frame
        XCTAssertEqual(qrFrame.width, qrFrame.height, accuracy: 2)
        XCTAssertLessThanOrEqual(qrFrame.width, 328)
        XCTAssertGreaterThanOrEqual(qrFrame.minX, windowFrame.minX)
        XCTAssertLessThanOrEqual(qrFrame.maxX, windowFrame.maxX)
        XCTAssertGreaterThanOrEqual(qrFrame.minY, windowFrame.minY)
        XCTAssertLessThanOrEqual(qrFrame.maxY, windowFrame.maxY)
    }
}
