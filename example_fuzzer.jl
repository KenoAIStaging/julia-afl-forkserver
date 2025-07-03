#!/usr/bin/env julia

include("julia_afl_new_fixed.jl")

# Simple test target
function fuzz_target(input::Vector{UInt8})
    trace(0x3000)
    
    if length(input) >= 4
        trace(0x3100)
        
        # Bug 1: ABCD pattern
        if input[1:4] == UInt8[0x41, 0x42, 0x43, 0x44]
            trace(0x4000)
            error("Found ABCD!")
        end
        
        # Bug 2: Bounds error
        if input[1] == 0xFF && length(input) >= 2
            trace(0x5000)
            idx = Int(input[2])
            if idx > 10
                trace(0x5100)
                x = input[idx]  # May crash
            end
        end
    end
    
    trace(0x9000)
end

# Run it
afl_main(fuzz_target)