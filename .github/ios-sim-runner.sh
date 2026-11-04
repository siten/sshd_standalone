#!/bin/sh
# Cargo runner for aarch64-apple-ios-sim. simctl will not launch an unsigned binary.
set -eu
codesign --force --sign - "$1"
exec xcrun simctl spawn booted "$@"
