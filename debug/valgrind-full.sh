#!/bin/bash

declare -a tests=("test01_add_with_u16_public_inputs" 
                "test02_add_with_u16_private_inputs" 
                "test03_add_with_u16_private_and_public_inputs"
                "test04_add_with_u32_public_inputs"
                "test05_add_with_u32_private_inputs"
                "test06_add_with_u32_private_and_public_inputs"
                "test07_add_with_u64_public_inputs"
                "test08_add_with_u64_private_inputs"
                "test09_add_with_u64_private_and_public_inputs"
                "test_subtract_with_u16_public_inputs"
                "test_subtract_with_u16_private_inputs"
                "test_subtract_with_u16_private_and_public_inputs"
                "test_subtract_with_u32_public_inputs"
                "test_subtract_with_u32_private_inputs"
                "test_subtract_with_u32_private_and_public_inputs"
                "test_subtract_with_u64_public_inputs"
                "test_subtract_with_u64_private_inputs"
                "test_subtract_with_u64_private_and_public_inputs"
                "test_record_add"
                "test_record_subtract"
                "test_genesis"
                "test_mint"
                "test_transfer"
                "test_combine"
                "test_split"
                "test_fee"
                )

mkdir -p reports reports/valgrind

for test in "${tests[@]}"
do
    echo "Valgrinding ${test} in ${test}.txt"
    make valgrind FN=${test} OUTDIR=reports/valgrind/ && wait $!
    echo "Valgrinded ${test}, you can find the log in ${test}.txt"
done
