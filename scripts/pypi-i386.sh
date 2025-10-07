#!/bin/bash
set -e
./configure --debug-level=0 --enable-static --without-i18n --without-doc --packager=pip --build=i386-linux-gnu
make clean
make

mv build/ceccomp py-temp/ceccomp/
cd py-temp
python -m build --wheel

oldfile=$(ls dist/ceccomp-*-py3-none-any.whl | head -n 1)
newfile="${oldfile/any/manylinux1_i686}"
mv "$oldfile" "$newfile"

twine upload $newfile --repository ceccomp
rm -rf dist/ build/ ceccomp.egg-info/ wheelhouse/ ceccomp/ceccomp
