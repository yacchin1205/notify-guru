#!/bin/zsh

set -euo pipefail

repository_dir=${0:A:h:h}
cd "$repository_dir"

results_dir=${TEST_RESULTS_DIR:-/tmp/notify-guru-test-results-$(date +%Y%m%d-%H%M%S)-$$}
phone_simulator=${IOS_PHONE_SIMULATOR:-iPhone 17 Pro}
tablet_simulator=${IOS_TABLET_SIMULATOR:-iPad Pro 13-inch (M5)}
phone_destination="platform=iOS Simulator,name=$phone_simulator,OS=latest"
tablet_destination="platform=iOS Simulator,name=$tablet_simulator,OS=latest"
worker_pid=""

cleanup() {
  if [[ -n "$worker_pid" ]] && kill -0 "$worker_pid"; then
    kill "$worker_pid"
    wait "$worker_pid" || true
  fi
}

trap cleanup EXIT INT TERM

prepare_ios_ui_tests() {
  local simulator=$1
  local installed_apps

  xcrun simctl bootstatus "$simulator" -b
  installed_apps=$(xcrun simctl listapps "$simulator")
  if [[ "$installed_apps" == *'"guru.notify.app" ='* ]]; then
    xcrun simctl uninstall "$simulator" guru.notify.app
  fi
}

run_ui_tests() {
  local label=$1
  local scheme=$2
  local destination=$3
  local only_testing=$4
  local result_bundle="$results_dir/$label.xcresult"
  local attachments="$results_dir/$label-attachments"
  local test_status=0

  xcodebuild \
    -project ios/NotifyGuru.xcodeproj \
    -scheme "$scheme" \
    -destination "$destination" \
    -parallel-testing-enabled NO \
    -resultBundlePath "$result_bundle" \
    -only-testing:"$only_testing" \
    test || test_status=$?

  if [[ -d "$result_bundle" ]]; then
    xcrun xcresulttool export attachments \
      --path "$result_bundle" \
      --output-path "$attachments"
  fi

  return "$test_status"
}

mkdir -p "$results_dir"
print "Test results: $results_dir"

print "Running Worker and Web tests"
npm run check

print "Running Go tests"
go test -count=1 ./...

print "Running Go integration tests"
npm run dev -- --ip 127.0.0.1 --port 8787 &
worker_pid=$!
curl --fail --show-error --silent \
  --retry 60 \
  --retry-delay 2 \
  --retry-all-errors \
  --retry-connrefused \
  http://127.0.0.1:8787/api/health
kill -0 "$worker_pid"
NOTIFY_INTEGRATION_BASE_URL=http://127.0.0.1:8787 go test -count=1 -tags integration ./internal/notify
cleanup
worker_pid=""

print "Running iOS unit tests"
xcodebuild \
  -project ios/NotifyGuru.xcodeproj \
  -scheme NotifyGuru \
  -destination "$phone_destination" \
  -parallel-testing-enabled NO \
  -resultBundlePath "$results_dir/ios-unit.xcresult" \
  -only-testing:NotifyGuruTests \
  test

print "Running iPhone UI tests"
prepare_ios_ui_tests "$phone_simulator"
run_ui_tests ios-ui-iphone NotifyGuru "$phone_destination" NotifyGuruUITests

print "Running iPad UI tests"
prepare_ios_ui_tests "$tablet_simulator"
run_ui_tests ios-ui-ipad NotifyGuru "$tablet_destination" NotifyGuruUITests

print "Running macOS UI tests"
run_ui_tests macos-ui NotifyGuruMac "platform=macOS" NotifyGuruMacUITests

print "All tests passed"
