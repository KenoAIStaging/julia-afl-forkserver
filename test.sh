#!/bin/bash

# Test script for Julia AFL++ forkserver

echo "=== Testing Julia AFL++ Forkserver ==="
echo ""

# Check for AFL++ (look in current dir first for testing)
AFL_FUZZ="afl-fuzz"
if [ -x "../AFLplusplus/afl-fuzz" ]; then
    AFL_FUZZ="../AFLplusplus/afl-fuzz"
    AFL_SHOWMAP="../AFLplusplus/afl-showmap"
elif ! command -v afl-fuzz &> /dev/null; then
    echo "ERROR: AFL++ not found. Please install AFL++ first."
    exit 1
else
    AFL_SHOWMAP="afl-showmap"
fi

# Check for Julia
if ! command -v julia &> /dev/null; then
    echo "ERROR: Julia not found. Please install Julia first."
    exit 1
fi

# Create test corpus
echo "1. Creating test corpus..."
mkdir -p test_corpus
echo "test" > test_corpus/seed1.txt
echo -ne "\x42\x42" > test_corpus/crash.bin
echo -ne "\x01\x02\x03" > test_corpus/seed2.bin

# Test standalone mode
echo ""
echo "2. Testing standalone mode..."
echo -n "   Normal input: "
echo "hello" | julia simple_example.jl 2>/dev/null && echo "PASS" || echo "FAIL"

echo -n "   Crash input:  "
echo -ne "\x42\x42" | julia simple_example.jl 2>/dev/null && echo "FAIL" || echo "PASS (crash expected)"

# Test with afl-showmap
echo ""
echo "3. Testing with afl-showmap..."
export AFL_SKIP_BIN_CHECK=1
$AFL_SHOWMAP -o /tmp/trace.txt -- julia simple_example.jl < test_corpus/seed1.txt 2>&1 | grep -E "(Captured|fork server)"

# Instructions for full fuzzing
echo ""
echo "4. To run full fuzzing:"
echo "   export AFL_SKIP_BIN_CHECK=1"
echo "   $AFL_FUZZ -i test_corpus -o findings -- julia simple_example.jl"
echo ""
echo "   AFL++ should find crashes quickly!"

# Cleanup
rm -rf test_corpus