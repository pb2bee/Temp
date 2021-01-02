#!/bin/zsh

AFL_DEBUG_CHILD_OUTPUT=1 AFL_AUTORESUME=1 AFL_PATH="../AFLplusplus" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./upnpd_fuzz.py @@
