cd threads
make clean
make
cd build
source ../../activate
# pintos -- -q run alarm-single
# pintos -- -q run alarm-multiple
# pintos -- -q run alarm-simultaneous
pintos -- -q run alarm-priority
# pintos -- -q run alarm-zero
# pintos -- -q run alarm-negative