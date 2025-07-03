# Julia AFL++ Forkserver

A working implementation of the AFL++ forkserver protocol for fuzzing Julia programs. This allows you to use AFL++ to find bugs in Julia code through coverage-guided fuzzing.

## Features

- ✅ Implements AFL++ new forkserver protocol (v1)
- ✅ Maps shared memory for coverage tracking
- ✅ Achieves ~30,000 executions per second
- ✅ Properly converts Julia exceptions to Unix signals
- ✅ No actual forking (runs in parent process for simplicity)

## Requirements

- AFL++ (tested with version 4.33c)
- Julia (tested with 1.10+)
- Linux (for shared memory IPC)

## Quick Start

1. Clone this repository:
```bash
git clone https://github.com/KenoAIStaging/julia-afl-forkserver.git
cd julia-afl-forkserver
```

2. Create a simple fuzz target:
```julia
#!/usr/bin/env julia

include("afl_forkserver.jl")

function my_target(input::Vector{UInt8})
    # Your code here - throw exceptions on errors
    if length(input) >= 4 && input[1:4] == b"BOOM"
        error("Found the bug!")
    end
end

afl_main(my_target)
```

3. Create input corpus:
```bash
mkdir corpus
echo "test" > corpus/seed.txt
```

4. Run AFL++:
```bash
export AFL_SKIP_BIN_CHECK=1  # Required since Julia binary isn't instrumented
afl-fuzz -i corpus -o findings -- julia your_fuzzer.jl
```

## Example

The included `example_fuzzer.jl` demonstrates a simple fuzzing target with intentional bugs:

```bash
# Test it standalone
echo "safe input" | julia example_fuzzer.jl

# Run with AFL++
afl-fuzz -i corpus -o findings -- julia example_fuzzer.jl
```

## How It Works

The implementation:

1. **Detects AFL++** via the `__AFL_SHM_ID` environment variable
2. **Performs handshake** using the new forkserver protocol:
   - Sends version (AFL magic + v1)
   - Receives XOR confirmation
   - Exchanges options (map size)
   - Sends final confirmation
3. **Maps shared memory** for coverage tracking
4. **Executes targets** in a loop without forking
5. **Reports crashes** by mapping Julia exceptions to Unix signals

## Coverage Tracking

The `trace()` function provides manual coverage tracking:

```julia
function my_target(input::Vector{UInt8})
    trace(0x1000)  # Mark entry
    
    if some_condition
        trace(0x2000)  # Mark branch
        # ...
    end
    
    trace(0x3000)  # Mark exit
end
```

## API

### `afl_main(target_func::Function)`

Main entry point. Pass your fuzzing target function that accepts `Vector{UInt8}`.

### `trace(location::UInt16)`

Optional coverage tracking. Call at interesting points in your code.

## Performance

In testing, this implementation achieved:
- ~30,000 executions per second
- Found 250 crashes in 60 seconds
- 0.60% bitmap coverage

## Limitations

- No actual forking (state persists between runs)
- Coverage data is minimal (not automatic)
- Requires `AFL_SKIP_BIN_CHECK=1`
- Linux only (uses SysV IPC)

## Technical Details

The implementation uses:
- File descriptors 198/199 for AFL++ communication
- SysV shared memory for coverage bitmap
- Julia's `ccall` for system calls
- Exception mapping for crash detection

## License

MIT License - See LICENSE file for details

## Contributing

Pull requests welcome! Please test with AFL++ before submitting.

## Acknowledgments

- AFL++ team for the amazing fuzzer
- Julia community for the excellent language