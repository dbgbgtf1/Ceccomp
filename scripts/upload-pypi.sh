#!/bin/bash
set -e

# 通用构建函数
build_and_upload() {
    BUILD_TARGET=$1
    WHEEL_TAG=$2

    echo "===== 构建架构：($BUILD_TARGET) ====="

    ./configure \
        --debug-level=0 \
        --enable-static \
        --without-i18n \
        --without-doc \
        --packager=pip \
        --build=${BUILD_TARGET}

    make clean
    make

    mv build/ceccomp py-temp/ceccomp/
    cd py-temp

    python -m build --wheel

    oldfile=$(ls dist/ceccomp-*-py3-none-any.whl | head -n 1)
    newfile="${oldfile/any/${WHEEL_TAG}}"

    mv "$oldfile" "$newfile"
    twine upload "$newfile" --repository ceccomp

    rm -rf dist/ build/ ceccomp.egg-info/ wheelhouse/ ceccomp/ceccomp
    cd ..
}

build_x86_64() {
    build_and_upload "x86_64-linux-gnu" "manylinux1_x86_64"
}

build_i386() {
    build_and_upload "i386-linux-gnu" "manylinux1_i686"
}

build_aarch64() {
    build_and_upload "aarch64-linux-gnu" "manylinux2014_aarch64"
}

build_armhf() {
    build_and_upload "arm-linux-gnueabihf" "manylinux2014_armv7l"
}

build_riscv64() {
    build_and_upload "riscv64-linux-gnu" "manylinux_2_31_riscv64"
}


# 根据参数选择执行
case "$1" in
    aarch64)
        build_aarch64
        ;;
    x86_64)
        build_x86_64
        ;;
    all)
        build_aarch64
        build_x86_64
        ;;
    *)
        echo "用法: $0 {aarch64|x86_64|all}"
        exit 1
        ;;
esac
