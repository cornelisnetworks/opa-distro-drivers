#!/bin/bash

find . -name *.c > cscope.files
find . -name *.h >> cscope.files
cscope -b -q -k
