#!/bin/sh
set -eu
npm install
env CI=1 npm test
# Fix resource URLs when viewing the page via a file:// URL.
env PUBLIC_URL=. npm run build
release_name="tiuku"

rm -rf release
mkdir release

cd release
mv ../build "$release_name"
cp -a ../collectors "$release_name"

cd $release_name
zip -r "../$release_name.zip" "."
