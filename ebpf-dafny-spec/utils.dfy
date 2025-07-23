include "types.dfy"
include "ctxmem-precond.dfy"

function signExtend32To64(num: bv64) :bv64
    {
        signExtend64(num, 32)
    }

function signExtend64(num: bv64, curwidth: int) :bv64
    requires curwidth == 8 || curwidth == 16 || curwidth == 32 || curwidth == 64
    {
        if curwidth == 64 then num
        else if curwidth == 32 then (
            if num & 0x0000_0000_8000_0000 == 0
                then (num & 0x0000_0000_FFFF_FFFF)
            else (num | 0xFFFF_FFFF_0000_0000)
        )
        else if curwidth == 16 then (
            if num & 0x0000_0000_0000_8000 == 0
                then (num & 0x0000_0000_0000_FFFF)
            else (num | 0xFFFF_FFFF_FFFF_0000)
        )
        // curwidth == 8 
        else (
            if num & 0x0000_0000_0000_0080 == 0
                then (num & 0x0000_0000_0000_00FF)
            else (num | 0xFFFF_FFFF_FFFF_FF00)
        )
        // else if num & (0x1 << ((curwidth-1) as bv6)) == 0 then (num & 0x0000_0000_FFFF_FFFF)
        // else num | !(((0x1 as bv64) << (curwidth as bv6)) - 0x1)
    }


// Flip bits and then add 1, finally remove the sign bit
function twocom2Abs32Bit(num: bv64) :bv64
    {
        if num & 0x80000000 == 0 then num & 0xEFFF_FFFF
        else ((!num) + 1) & 0xEFFF_FFFF
    }

// Flip bits and then add 1, finally remove the sign bit
function twocom2Abs64Bit(num: bv64) :bv64
    {
        if num & 0x8000000000000000 == 0 then num
        else ((!num) + 1) & 0x7FFF_FFFF_FFFF_FFFF
    }

function abs2NegTwocom32Bit(num: bv64) :bv64
    {
        (((!num) + 1) & 0xFFFFFFFF) | 0x8000_0000
    }

function abs2NegTwocom64Bit(num: bv64) :bv64
    {
        ((!num) + 1) | 0x8000_0000_0000_0000
    }

function bv64ToInt64(num: bv64) :int64
    {
        if num & 0x8000_0000_0000_0000 == 0 then (num as int64)
        else -(twocom2Abs64Bit(num) as int64)
    }

function bv64ToUInt64(num: bv64) :uint64
    {
        (num as uint64)
    }

function bv32ToInt32(num: bv64) :int64
    // requires num & 0xFFFF_FFFF_0000_0000 == 0
    {
        if num & 0x8000_0000 == 0 then ((num & 0x0000_0000_FFFF_FFFF) as int64)
        else -(twocom2Abs32Bit(num) as int64)
    }

// truncate

function bv64Tobv32(num: bv64) :bv64
    {
        num & 0x0000_0000_FFFF_FFFF
    }

// Byte swap

function {:fuel 8} byteswapN(num: bv64, curb: int, N: int) :bv64
    requires 0 <= curb < 8
    requires N == 2 || N == 4 || N == 8
    requires curb < N
    decreases 8-curb
    {
        if curb+1 ==  N then (((num >> (curb * 8)) & 0xff) << ((N-curb-1) * 8))
        else ((((num >> (curb * 8)) & 0xff) << ((N-curb-1) * 8)) | (byteswapN(num, curb+1, N)))
    }


// Signed division

function signDiv32Bit(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs32Bit(divisor) != 0x0
    {
        if (dividend & 0x80000000) == (divisor & 0x80000000) then (twocom2Abs32Bit(dividend) / twocom2Abs32Bit(divisor))
        else abs2NegTwocom32Bit((twocom2Abs32Bit(dividend) / twocom2Abs32Bit(divisor)))
    }

function signDiv64Bit(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs64Bit(divisor) != 0x0
    {
        if (dividend & 0x8000000000000000) == (divisor & 0x8000000000000000)
            then (twocom2Abs64Bit(dividend) / twocom2Abs64Bit(divisor))
            // Convert dividend and divisor to absolute value and then calculate and then negate the result
            else abs2NegTwocom64Bit(twocom2Abs64Bit(dividend) / twocom2Abs64Bit(divisor))
    }


/*
function signMod32Bit(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs32Bit(divisor) != 0x0
    {
        if (dividend & 0x80000000) == (divisor & 0x80000000)
            then (twocom2Abs32Bit(dividend) % twocom2Abs32Bit(divisor))
            else abs2NegTwocom32Bit(twocom2Abs32Bit(dividend) % twocom2Abs32Bit(divisor))
    }

function signMod64Bit(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs64Bit(divisor) != 0x0
    {
        if (dividend & 0x8000000000000000) == (divisor & 0x8000000000000000)
            then (twocom2Abs64Bit(dividend) % twocom2Abs64Bit(divisor))
            else abs2NegTwocom64Bit(twocom2Abs64Bit(dividend) % twocom2Abs64Bit(divisor))
    }
*/

// Signed modulo: a % n = a - n * trunc(a / n)

function signMod32Bit(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs32Bit(divisor) != 0x0
    {
        (dividend - (divisor * signDiv32Bit(dividend, divisor))) & 0x0000_0000_FFFF_FFFF
    }

function signMod64Bit(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs64Bit(divisor) != 0
    {
        dividend - (divisor * signDiv64Bit(dividend, divisor))
    }


// Airthmetic right shift

function signShift32Bit(num: bv64, shift: bv64) :bv64
    {
        if (num & 0x80000000 == 0) then (num >> ((shift & 0x1F) as bv5)) & 0xFFFFFFFF
        else ((num >> ((shift & 0x1F) as bv5)) | !(((0x1 as bv64) << ((32-(shift & 0x1F)) as bv8)) - 0x1)) & 0xFFFFFFFF
    }

function signShift64Bit(num: bv64, shift: bv64) :bv64
    {
        if (num & 0x8000000000000000) == 0 then (num >> ((shift & 0x3F) as bv6))
        else ((num >> ((shift & 0x3F) as bv6)) | !(((0x1 as bv64) << ((64-(shift & 0x3F)) as bv8)) - 0x1))
    }

// Memory related functions

function getRegByteX(num: bv64, byteIdx:int) :bv8
    requires 0 <= byteIdx < 8
    {
        ((num >> (byteIdx*8)) & 0xff) as bv8
    }

// When loading, not necessary to use old() expression as we are not modifying anything with `modifies`
// NOTE: cannot call this function, if there is modifies on this mem
/*
ghost function loadNbytesStack(mem: array<bv8>, memLen: int64, off: int64, idx:int64, size: int64) :bv64
    reads mem
    requires mem.Length == memLen
    requires size == 1 || size == 2 || size == 4 || size == 8
    requires 0<= idx < size
    requires 0 <= off + idx < off+size <= memLen
    decreases size-idx
    ensures size == 4 ==> loadNbytesStack(mem, memLen, off, idx, size) & 0xFFFF_FFFF_0000_0000 == 0x0
    ensures size == 2 ==> loadNbytesStack(mem, memLen, off, idx, size) & 0xFFFF_FFFF_FFFF_0000 == 0x0
    ensures size == 1 ==> loadNbytesStack(mem, memLen, off, idx, size) & 0xFFFF_FFFF_FFFF_FF00 == 0x0
    {
        var curByte := ((mem[off+idx] as bv64) << ((idx * 8) as bv6));
        if idx+1 == size then curByte
        else curByte | loadNbytesStack(mem, memLen, off, idx+1, size)
    }
*/

ghost function loadNbytesMem(mem: array<bv8>, off: int64, size: int64) :bv64
    reads mem
    requires size == 1 || size == 2 || size == 4 || size == 8
    requires 0 <= off < off+size <= mem.Length
    //
    {
        if (size == 1)
            then (mem[off] as bv64)
        else if (size == 2) then
            (mem[off] as bv64) | (((mem[off+1] as bv64) & 0xff) << 8)
        else if (size == 4) then
            (mem[off] as bv64)                     | (((mem[off+1] as bv64) & 0xff) << 8)   |
            (((mem[off+2] as bv64) & 0xff) << 16)  | (((mem[off+3] as bv64) & 0xff) << 24)
        else
            (mem[off] as bv64)                     | (((mem[off+1] as bv64) & 0xff) << 8)   |
            (((mem[off+2] as bv64) & 0xff) << 16)  | (((mem[off+3] as bv64) & 0xff) << 24)  |
            (((mem[off+4] as bv64) & 0xff) << 32)  | (((mem[off+5] as bv64) & 0xff) << 40)  |
            (((mem[off+6] as bv64) & 0xff) << 48)  | (((mem[off+7] as bv64) & 0xff) << 56)
    }      



/**
ghost function loadNbytesStack(mem: array<bv8>, memLen: int64, off: int64, idx:int64, size: int64) :bv64
    reads mem
    requires mem.Length == 512
    requires size == 1 || size == 2 || size == 4 || size == 8
    requires 0<= idx <= size
    requires 0 <=  off+idx <= off+size <= 512
    decreases size-idx
    ensures size == 4 ==> loadNbytesStack(mem, off, idx, size) & 0xFFFF_FFFF_0000_0000 == 0x0
    ensures size == 2 ==> loadNbytesStack(mem, off, idx, size) & 0xFFFF_FFFF_FFFF_0000 == 0x0
    ensures size == 1 ==> loadNbytesStack(mem, off, idx, size) & 0xFFFF_FFFF_FFFF_FF00 == 0x0
    {
        if idx == size then (0x0 as bv64)
        else ((mem[off+idx] as bv64) << ((idx * 8) as bv6)) | loadNbytesStack(mem, off, idx+1, size)
    }
 */

////////////////////////////////

predicate ScalarTypes(regType: REGTYPE)
    {
        regType == SCALAR || regType == STACK_DYNPTR || regType == STACK_ITER
    }

predicate Ptr_or_NULL(regType: REGTYPE)
    {
        regType != UNINT && regType != SCALAR && regType != STACK_DYNPTR && regType != STACK_ITER
    }

predicate NonNULLPtr(regType: REGTYPE)
    {
        // exclude UNINT either
        Ptr_or_NULL(regType) && regType != NULL
    }

predicate isMapPtr(regType: REGTYPE)
    {
        regType == MAP_PTR || regType == PTR_TO_MAP_KEY || regType == PTR_TO_MAP_VALUE
    }

predicate isPktPtr(regType: REGTYPE)
    {
        regType == PTR_TO_PACKET_META || regType == PTR_TO_PACKET || regType == PTR_TO_PACKET_END
    }


function MaskUpBySize(num: bv64, size: int64) :bv64
    requires size == 1 || size == 2 || size == 4 || size == 8
    {
        if size == 1 then num & 0x0000_0000_0000_00FF
        else if size == 2 then num & 0x0000_0000_0000_FFFF
        else if size == 4 then num & 0x0000_0000_FFFF_FFFF
        else num // size == 8
    }


////////////////////////////////// SOCKET Pointers ////////////////////////

ghost predicate validate_sock_common_access(off: int64, size: int64)
    {
        // Cannot access fileds [type, protocol, mark, priority]
        (off < 8 || off >= 24)
        &&
        validate_sock_access(off, size)
    }

// bpf_sock_is_valid_access, struct bpf_sock
ghost predicate validate_sock_access(off: int64, size: int64)
    {
        (0 <= off < off + size < 80) &&
        (
            // 0 4 bound_dev_if
            exact_4_read(off, size, 0, READ)
            ||
            
            // 4 4 family
            narrow_4_read_from_off(off, size, 4, READ)
            ||
            
            // 8 4 type
            narrow_4_read_from_off(off, size, 8, READ)
            ||
            
            // 12 4 protocol
            narrow_4_read_from_off(off, size, 12, READ)
            ||
            
            // 16 4 mark
            exact_4_read(off, size, 16, READ)
            ||
            
            // 20 4 priority
            exact_4_read(off, size, 20, READ)
            ||
            
            // 24 4 src_ip4
            narrow_4_read(off, size, 24, READ)
            ||

            // 28 16 src_ip6[4]
            (
                (28 <= off < off + size < 44) &&
                (size == 1 || size == 2 || size == 4)
            )
            ||

            // 44 4 src_port
            narrow_4_read_from_off(off, size, 44, READ)
            ||

            // 48 2 dst_port
            // 50 2 padding
            (off == 48 && (size == 2 || size == 4))
            ||

            // 52 4 dst_ip4
            narrow_4_read(off, size, 52, READ)
            ||

            // 56 16 dst_ip6[4]
            (
                (56 <= off < off + size < 72) &&
                (size == 1 || size == 2 || size == 4)
            )
            ||

            // 72 4 state
            narrow_4_read_from_off(off, size, 72, READ)   ||

            // 76 4 rx_queue_mapping
            narrow_4_read_from_off(off, size, 164, READ)
        )
        //
    }

// bpf_tcp_sock_is_valid_access, struct bpf_tcp_sock
ghost predicate validate_tcp_sock_access(off: int64, size: int64)
    {
        (if off == 80 || off == 88 then size == 8 else size == 4)       &&
        (0 <= off < off + size < 112) // sizeof(struct bpf_tcp_sock)
    }

// bpf_xdp_sock_is_valid_access, struct bpf_xdp_sock
ghost predicate validate_xdp_sock_access(off: int64, size: int64)
    {
        off == 0 && size == 4
        /*
            struct bpf_xdp_sock {
                __u32 queue_id;
            };
            */
    }

ghost predicate unknown_bool()

method AnyBv64() returns (x: bv64)
{
  x :| true;  // Non-deterministically assign any value to x
}

method AnyInt64() returns (x: int64)
{
  x :| true;  // Non-deterministically assign any value to x
}

method AnyRegtype() returns (x: REGTYPE)
{
  x :| true;  // Non-deterministically assign any value to x
}

method AnyBv8() returns (x: bv8)
{
  x :| true;  // Non-deterministically assign any value to x
}


ghost predicate unknownBv64(x: bv64) {
    0x0000_0000_0000_0000 <= x <= 0xFFFF_FFFF_FFFF_FFFF
}

ghost predicate unknownBv32(x: bv64) {
    0x0000_0000_0000_0000 <= x <= 0x0000_0000_FFFF_FFFF
}

ghost predicate unknownBv(x: bv64, size:int) {
    if size == 1 then 0 <= x <= 0xFF
    else if size == 2 then 0 <= x <= 0xFF_FF
    else if size == 4  then 0 <= x <= 0xFF_FF_FF_FF
    else if size == 8 then 0 <= x <= 0xFFFF_FFFF_FFFF_FFFF
    else false
}