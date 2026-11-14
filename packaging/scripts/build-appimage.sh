#!/bin/sh
# Build dist/diysca-<version>-x86_64.AppImage from the standalone bundle.
# Needs appimagetool on PATH (https://github.com/AppImage/appimagetool).
set -eu
cd "$(dirname "$0")/../.."
[ -x dist/diysca/diysca ] || packaging/scripts/build-standalone.sh
VERSION=${VERSION:-$(./dist/diysca/diysca --version)}
ARCH=${ARCH:-x86_64}
APPDIR=build/AppDir
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/scalable/apps"
cp -a dist/diysca "$APPDIR/usr/lib/diysca"
cp packaging/appimage/AppRun "$APPDIR/AppRun"
cp packaging/appimage/diysca.desktop "$APPDIR/diysca.desktop"
cp packaging/appimage/diysca.desktop "$APPDIR/usr/share/applications/"
cp packaging/diysca.svg "$APPDIR/diysca.svg"
cp packaging/diysca.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/"
ARCH=$ARCH appimagetool --no-appstream "$APPDIR" "dist/diysca-$VERSION-$ARCH.AppImage"
