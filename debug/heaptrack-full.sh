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
                )

mkdir -p reports reports/heaptrack reports/heaptrack/outfile reports/heaptrack/analysis

for test in "${tests[@]}"
do
    FILE_PREFIX="heaptrack.${test}"
    OUTFILE="reports/heaptrack/outfile/${FILE_PREFIX}"
    ANALYSIS="reports/heaptrack/analysis/${FILE_PREFIX}"
    echo "Heaptracking ${test}"
    # Runs the process and starts the heaptrack.
    ./target/release/vmtropy_debug --f ${test} & heaptrack -o "${OUTFILE}" -p $!
    # Analyze the file.
    heaptrack -a "${OUTFILE}.gz" > ${ANALYSIS}.txt
    echo "Heaptracked ${test}"
done
