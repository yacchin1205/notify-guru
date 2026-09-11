# 作業規則

- ユーザーの明示的な承認なしに、デプロイや外部設定の変更を行わない。
- TestFlight へアップロードする場合は、ユーザーの明示的な承認を得て、重複しないビルド番号を設定し、Archive の検証結果とアップロードしたバージョンを報告する。
- ユーザー向けの変更は、影響する Web と iPhone のフローを実際の画面で操作するまで検証済みとしない。単体テスト、ビルド、コードレビュー、ソースコードの確認は、GUI テストの代替にならない。
- Web の GUI テストには Chrome DevTools を使用する。独自のブラウザ操作基盤を作らない。
- iOS の GUI テストには XCUITest を使用し、操作と assert に加えて各段階のスクリーンショットを `.xcresult` から取り出して目視する。
- GUI テストを始める前に、操作シナリオと期待結果を明示する。テスト中に、それらを黙って削除、縮小、または再定義しない。
- GUI で実際に行った操作と観測した結果を正確に報告する。未実施、失敗、または確認不能だった項目を明示する。
- デプロイ前に、その時点で実施可能な自動テストと GUI テストを行い、結果と未検証項目を報告する。明示的な承認を得てデプロイした後、デプロイ環境を必要とする GUI テストを行う。未検証項目が残る間は、動作確認済みまたは完了とは扱わない。

## TestFlight 配布手順

1. `origin/main` を fetch し、配布対象を `origin/main` のコミットに固定する。ローカルの `main` が分岐している場合は履歴を変更せず、detached HEAD で `origin/main` を checkout する。
2. TestFlight の対象は iOS/iPadOS と macOS の両方とする。Marketing Version と Build Number は、毎回 Archive を始める前にユーザーへ問い合わせ、両方の明示的な承認を得る。過去の値や日付から推測して決めない。承認された同じ値を両プラットフォームと各埋め込み拡張へ明示する。
3. Keychain、Xcode サービス、Provisioning Profile を使う確認・Archive・Export・Upload はサンドボックス外で実行する。サンドボックス内の権限エラーを署名環境や Simulator の実状態と判断しない。
4. `ios/NotifyGuru.xcodeproj` の `NotifyGuru` スキームを `generic/platform=iOS` 向けに Archive する。この Archive には iOS/iPadOS 本体と `NotifyGuruShare` が含まれる。
5. 同プロジェクトの `NotifyGuruMac` スキームを `generic/platform=macOS` 向けに Archive する。この Archive には macOS 本体、Widget、共有拡張が含まれる。
6. 両方の Archive について、Xcode の Store 向け検証が成功したこと、本体と各埋め込み拡張の Marketing Version・Build Number、Bundle ID、署名、Provisioning Profile、Entitlements が意図どおりであることを確認する。どちらかに問題があればアップロードを開始しない。
7. 両方の検証後、`method=app-store-connect`、`destination=upload`、`manageAppVersionAndBuildNumber=false` の Export Options で各 Archive をアップロードする。Apple 側の分析、検証、アップロード受付が成功したことを個別に確認する。
8. 最後に、配布元コミット、iOS/iPadOS と macOS それぞれのアップロード結果、Marketing Version、Build Number、Archive の検証結果を報告する。
