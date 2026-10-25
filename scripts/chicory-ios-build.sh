#!/bin/sh
# Build only the isolated simulator qualification app and restore source inputs.
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chicory_dir=${CHICORY_SOURCE_DIR:-"$script_dir/../../../testing/chicory"}
chicory_dir=$(CDPATH= cd -- "$chicory_dir" && pwd)
build_dir=${CHICORY_IOS_BUILD_DIR:-/tmp/chicory-primary-ios-build}
bundle_id=${CHICORY_IOS_BUNDLE_ID:-com.chicory.primaryqualification}
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
test_entry="$chicory_dir/native-tests/LdkPrimary.tsx"

test -d "$chicory_dir/ios/Pods" || {
  echo 'Install the CocoaPods dependencies in Chicory before running this build.' >&2
  exit 1
}
test ! -e "$test_entry" || {
  echo 'The qualification entry already exists; preserve or remove it before rebuilding.' >&2
  exit 1
}
backup_dir=$(mktemp -d /tmp/chicory-ios-source.XXXXXX)
cp "$chicory_dir/ios/chicory/AppDelegate.swift" "$backup_dir/AppDelegate.swift"
cp "$chicory_dir/ios/chicory/Info.plist" "$backup_dir/Info.plist"
cp "$chicory_dir/ios/Podfile.lock" "$backup_dir/Podfile.lock"
restore_sources() {
  cp "$backup_dir/AppDelegate.swift" "$chicory_dir/ios/chicory/AppDelegate.swift"
  cp "$backup_dir/Info.plist" "$chicory_dir/ios/chicory/Info.plist"
  cp "$backup_dir/Podfile.lock" "$chicory_dir/ios/Podfile.lock"
  rm -f "$test_entry"
  rm -rf "$backup_dir"
}
trap restore_sources EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# CocoaPods on newer Ruby may change only local podspec checksums. Accept that
# exact difference temporarily; never change a resolved version or dependency.
python3 - "$chicory_dir/ios/Podfile.lock" "$chicory_dir/ios/Pods/Manifest.lock" <<'PY'
import pathlib, sys
lock, manifest = map(pathlib.Path, sys.argv[1:])
def without_checksums(data):
    result, skipping = [], False
    for line in data.splitlines(keepends=True):
        if line.startswith('SPEC CHECKSUMS:'):
            skipping = True
        elif skipping and line.strip() and not line[0].isspace():
            skipping = False
        if not skipping:
            result.append(line)
    return ''.join(result)
a, b = lock.read_text(), manifest.read_text()
if a != b:
    if without_checksums(a) != without_checksums(b):
        raise SystemExit('Installed pods differ from locked dependencies; install the pinned pods first.')
    lock.write_text(b)
PY
mkdir -p "$chicory_dir/native-tests"
cp "$script_dir/chicory-ios-entry.tsx" "$test_entry"
cp "$script_dir/chicory-ios-scene.swift" "$chicory_dir/ios/chicory/AppDelegate.swift"
python3 - "$chicory_dir/ios/chicory/Info.plist" "$backup_dir/qualification.entitlements" "$bundle_id" <<'PY'
import pathlib, plistlib, re, sys
bundle_id = sys.argv[3]
if not re.fullmatch(r'com\.chicory\.primaryqualification(?:\.[a-z0-9]+)?', bundle_id):
    raise SystemExit('Refusing an identifier outside the isolated qualification namespace.')
info = pathlib.Path(sys.argv[1])
data = plistlib.loads(info.read_bytes())
data['UIApplicationSceneManifest'] = {
    'UIApplicationSupportsMultipleScenes': False,
    'UISceneConfigurations': {'UIWindowSceneSessionRoleApplication': [{
        'UISceneConfigurationName': 'Qualification',
        'UISceneDelegateClassName': '$(PRODUCT_MODULE_NAME).QualificationScene',
    }]},
}
info.write_bytes(plistlib.dumps(data))
pathlib.Path(sys.argv[2]).write_bytes(plistlib.dumps({
    'application-identifier': 'LOCALTEST.' + bundle_id,
    'keychain-access-groups': ['LOCALTEST.' + bundle_id],
}))
PY
cd "$chicory_dir"
ENTRY_FILE=native-tests/LdkPrimary.tsx FORCE_BUNDLING=1 xcodebuild \
  -workspace ios/chicory.xcworkspace -scheme chicory -configuration Debug \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$build_dir" \
  PRODUCT_BUNDLE_IDENTIFIER="$bundle_id" \
  IPHONEOS_DEPLOYMENT_TARGET=15.1 \
  CODE_SIGN_ENTITLEMENTS="$backup_dir/qualification.entitlements" \
  CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=-
echo "Qualification app: $build_dir/Build/Products/Debug-iphonesimulator/chicory.app"
