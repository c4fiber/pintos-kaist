cd threads
make clean
make
cd build
source ../../activate
# pintos -- -q run alarm-single
# pintos -- -q run alarm-multiple
# pintos -- -q run alarm-simultaneous
# pintos -- -q run alarm-priority
# pintos -- -q run alarm-zero
# pintos -- -q run alarm-negative
# pintos -- -q run priority-change
pintos -- -q run priority-donate-one
# pintos -- -q run priority-donate-multiple
# pintos -- -q run priority-donate-multiple2
# pintos -- -q run priority-donate-nest
# pintos -- -q run priority-donate-sema
# pintos -- -q run priority-donate-lower
# pintos -- -q run priority-donate-chain
# pintos -- -q run priority-fifo
# pintos -- -q run priority-preempt
# pintos -- -q run priority-sema
# pintos -- -q run priority-condvar