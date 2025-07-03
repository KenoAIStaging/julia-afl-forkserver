#!/usr/bin/env julia

# Simple example of fuzzing Julia code with AFL++

include("afl_forkserver.jl")

function parse_data(input::Vector{UInt8})
    # This function has some bugs we want AFL++ to find
    
    if length(input) < 2
        return "Too short"
    end
    
    # Bug 1: Crash on magic bytes
    if input[1] == 0x42 && input[2] == 0x42  # "BB"
        error("Magic bytes detected!")
    end
    
    # Bug 2: Integer overflow
    if length(input) >= 4
        value = input[1] + input[2] * 256
        if value > 1000
            # This could cause issues
            idx = value % length(input)
            return input[idx]  # Potential bounds error
        end
    end
    
    # Bug 3: Division by zero
    if length(input) >= 3 && input[3] == input[1] - input[2]
        x = 1 ÷ (input[1] - input[2])
    end
    
    return "OK"
end

# Run the fuzzer
println(stderr, "Starting Julia AFL++ fuzzer...")
afl_main(parse_data)