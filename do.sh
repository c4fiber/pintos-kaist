#!/bin/bash

source ./activate

cd threads
make clean && make

cd build

pintos -- -q run priority-donate-nest
