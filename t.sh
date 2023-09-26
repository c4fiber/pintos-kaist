#!/bin/bash

source ./activate

cd threads
make clean && make check

