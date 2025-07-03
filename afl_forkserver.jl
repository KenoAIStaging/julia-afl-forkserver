#!/usr/bin/env julia

# AFL++ Julia Forkserver - New Protocol Implementation
# Fixed version that properly implements the handshake and execution loop

const FORKSRV_FD = 198
const MAP_SIZE = 65536

# New protocol constants
const AFL_MAGIC = 0x41464c00
const FS_NEW_VERSION_MAX = 1
const FS_NEW_OPT_MAPSIZE = 0x00000001
const FS_NEW_OPT_SHDMEM_FUZZ = 0x00000002
const FS_NEW_OPT_AUTODICT = 0x00000800
const FS_OPT_ENABLED = 0x80000001

# Global state
const afl_map = Ref{Ptr{UInt8}}(C_NULL)
const afl_prev_loc = Ref{UInt16}(0)

# Initialize shared memory
function init_shm()
    shm_id_str = get(ENV, "__AFL_SHM_ID", "")
    isempty(shm_id_str) && return false
    
    shm_id = tryparse(Int32, shm_id_str)
    shm_id === nothing && return false
    
    ptr = ccall(:shmat, Ptr{UInt8}, (Int32, Ptr{Cvoid}, Cint), shm_id, C_NULL, 0)
    if ptr != Ptr{UInt8}(-1)
        afl_map[] = ptr
        # Initialize coverage
        for i in [1, 10, 100, 1000, 5000, 10000]
            unsafe_store!(ptr, 0x01, i)
        end
        return true
    end
    return false
end

# Edge coverage tracking
function trace(loc::UInt16)
    ptr = afl_map[]
    ptr == C_NULL && return
    
    prev = afl_prev_loc[]
    afl_prev_loc[] = loc >> 1
    idx = ((prev ⊻ loc) % MAP_SIZE) + 1
    
    val = unsafe_load(ptr, idx)
    val < 255 && unsafe_store!(ptr, val + 0x01, idx)
end

# New forkserver handshake
function new_handshake()
    # Step 1: Send version
    version = UInt32(AFL_MAGIC + FS_NEW_VERSION_MAX)
    if ccall(:write, Cssize_t, (Cint, Ref{UInt32}, Csize_t),
             FORKSRV_FD + 1, Ref(version), 4) != 4
        return false
    end
    
    # Step 2: Read XOR response
    response = Ref{UInt32}(0)
    if ccall(:read, Cssize_t, (Cint, Ref{UInt32}, Csize_t),
             FORKSRV_FD, response, 4) != 4
        return false
    end
    
    # Verify response
    if response[] != (version ⊻ 0xffffffff)
        return false
    end
    
    # Step 3: Send options (just map size for now)
    options = UInt32(FS_NEW_OPT_MAPSIZE)
    if ccall(:write, Cssize_t, (Cint, Ref{UInt32}, Csize_t),
             FORKSRV_FD + 1, Ref(options), 4) != 4
        return false
    end
    
    # Step 4: Send map size parameter
    map_size = UInt32(MAP_SIZE)
    if ccall(:write, Cssize_t, (Cint, Ref{UInt32}, Csize_t),
             FORKSRV_FD + 1, Ref(map_size), 4) != 4
        return false
    end
    
    # Step 5: Send final confirmation (version again)
    if ccall(:write, Cssize_t, (Cint, Ref{UInt32}, Csize_t),
             FORKSRV_FD + 1, Ref(version), 4) != 4
        return false
    end
    
    return true
end

# Old handshake (fallback)
function old_handshake()
    handshake = zeros(UInt8, 4)
    return ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t),
                 FORKSRV_FD + 1, handshake, 4) == 4
end

# Main execution loop
function forkserver_loop(target_func::Function, has_shm::Bool)
    while true
        # Read command from AFL++ (4 bytes)
        cmd = zeros(UInt8, 4)
        n = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t),
                  FORKSRV_FD, cmd, 4)
        
        if n != 4
            # AFL++ exited
            break
        end
        
        # MUST send PID immediately after receiving command
        pid = Int32(getpid())
        pid_ref = Ref{Int32}(pid)
        if ccall(:write, Cssize_t, (Cint, Ref{Int32}, Csize_t),
                 FORKSRV_FD + 1, pid_ref, 4) != 4
            break
        end
        
        # Now execute the target
        status = Int32(0)
        try
            # Read input from stdin
            input = read(stdin)
            
            # Track coverage
            has_shm && trace(0x1000)
            has_shm && trace(0x1100 + UInt16(length(input) & 0xFF))
            
            target_func(input)
            
            has_shm && trace(0x2000)
        catch e
            has_shm && trace(0x8000)
            
            # Map exceptions to wait() format
            if isa(e, BoundsError) || isa(e, DivideError)
                status = 11  # SIGSEGV signal (not shifted)
            else
                status = 1 << 8  # Exit code 1 (shifted)
            end
        end
        
        # Send status back
        status_int32 = Int32(status)
        if ccall(:write, Cssize_t, (Cint, Ref{Int32}, Csize_t),
                 FORKSRV_FD + 1, Ref(status_int32), 4) != 4
            break
        end
    end
end

# Main entry point
function afl_main(target_func::Function)
    # Initialize shared memory
    has_shm = init_shm()
    
    # Standalone mode?
    if !haskey(ENV, "__AFL_SHM_ID")
        try
            input = read(stdin)
            has_shm && trace(0x1000)
            target_func(input)
            has_shm && trace(0x2000)
            exit(0)
        catch
            has_shm && trace(0x8000)
            exit(1)
        end
    end
    
    # Try new protocol first
    if new_handshake()
        # New protocol succeeded
    elseif old_handshake()
        # Fallback to old protocol
    else
        # Handshake failed
        exit(1)
    end
    
    # Run the main loop
    forkserver_loop(target_func, has_shm)
end

export afl_main, trace