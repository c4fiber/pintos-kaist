#!/bin/bash


cd ~/pintos-kaist
source ./activate

cd userprog
make

cd build

# -v: no vga, -k: kill-on-failure, --fs-disk: 임시 디스크 생성, -p: put, -g: get  // -f: format
#pintos -v -k --fs-disk=10 -p tests/userprog/read-normal:read-normal -p ../../tests/userprog/sample.txt:sample.txt -- -q -f run 'read-normal'
pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/userprog/open-normal:open-normal -p ../../tests/userprog/sample.txt:sample.txt -- -q   -f run open-normal

