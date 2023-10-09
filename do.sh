#!/bin/bash


cd ~/pintos-kaist
source ./activate

cd userprog
make clean && make

cd build

# -v: no vga, -k: kill-on-failure, --fs-disk: 임시 디스크 생성, -p: put, -g: get  // -f: format
pintos -v -k --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'

