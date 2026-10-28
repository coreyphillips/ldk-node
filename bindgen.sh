#!/usr/bin/env bash
set -euo pipefail

source ./scripts/install_gobley_bindgen.sh

# Standardize on release-smaller for all targets
export BINDGEN_PROFILE="release-smaller"

case "${1:-all}" in
  android)
    ./scripts/uniffi_bindgen_generate_kotlin_android.sh
    ;;
  all)
    ./scripts/uniffi_bindgen_generate.sh \
      && ./scripts/swift_create_xcframework_archive.sh
    ;;
  *)
    echo "Usage: ./bindgen.sh [all|android]" >&2
    exit 2
    ;;
esac
