#!/bin/bash

source ./activate

cd userprog
make clean && make

cd build

pintos -- -q run args
