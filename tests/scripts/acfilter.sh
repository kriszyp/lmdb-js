#!/bin/sh
grep -v "modifiersname" | \
grep -v "modifytimestamp" |  \
grep -v "creatorsname" | \
grep -v "createtimestamp"  
