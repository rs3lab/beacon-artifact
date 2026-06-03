include "types.dfy"
include "terms.dfy"
include "states.dfy"

module Utils {

    import opened Terms
    import opened DataTypes
    import opened States


    // ----------------- safety properties ---------------------

    ghost predicate sp4_vm_integrity(dst: REG) {dst != R10}

    ghost predicate sp2_datasafe(s: State, reg: REG)
    {   
        var regtv := get_reg_typeval(s, reg);
        regtv != Uninit && (
            if !s.cfg.allow_ptr_leak
            then is_scalar(regtv)
            else true
        )
    }

    // -----------   reg type and value check retrival -------------

    ghost function get_reg_typeval(s: State, reg: REG): ETYPEV
        {
            match reg {
                case R0 => s.R0
                case R1 => s.R1
                case R2 => s.R2
                case R3 => s.R3
                case R4 => s.R4
                case R5 => s.R5
                case R6 => s.R6
                case R7 => s.R7
                case R8 => s.R8
                case R9 => s.R9
                case R10 => s.R10
                // case Rn => s.Rn
            }
        }

    function is_scalar(e: ETYPEV): bool {
        match e
        case Scalar(_, _) => true
        case _           => false
    }


    function is_scalar_zero(e: ETYPEV): bool {
        match e
        case Scalar(_, 0) => true
        case _           => false
    }

    function ptr_or_ptrornull(e: ETYPEV): bool {
        match e
        case PtrOrNullType(_, _, _)   => true
        case PtrType(_, _, _)         => true
        case _                  => false
    }

    function ptrornull(e: ETYPEV): bool {
        match e
        case PtrOrNullType(_, _, _)   => true
        case _                  => false
    }

    function is_ptr(e: ETYPEV): bool {
        match e
        case PtrType(_, _, _)         => true
        case _                  => false
    }

    function ptrnull_to_ptr(e: ETYPEV) : (res: ETYPEV)
        requires ptrornull(e)
        ensures is_ptr(res)
    {
        match e
        case PtrOrNullType(t, memid, off) => ETYPEV.PtrType(t, memid, off)
        case _ => e
    }

    // ------------------- reg state reconstruction -------------------

    ghost function new_state_regonly(
        s: State, reg: REG, reg_state: ETYPEV
    ): (res: State)
    //
    requires reg != R10
    ensures s.R10 == res.R10
    ensures s.mems == res.mems
    ensures forall r | r != reg
            :: get_reg_typeval(s, r) == get_reg_typeval(res, r)
    ensures get_reg_typeval(res, reg) == reg_state
    {
      match reg
        case R0 =>  s.(R0  := reg_state)
        case R1 =>  s.(R1  := reg_state)
        case R2 =>  s.(R2  := reg_state)
        case R3 =>  s.(R3  := reg_state)
        case R4 =>  s.(R4  := reg_state)
        case R5 =>  s.(R5  := reg_state)
        case R6 =>  s.(R6  := reg_state)
        case R7 =>  s.(R7  := reg_state)
        case R8 =>  s.(R8  := reg_state)
        case R9 =>  s.(R9  := reg_state)
        case R10 => s.(R10 := reg_state)
        // case Rn =>  s.(Rn  := reg_state)
    }
    
    // --------------------arith operation helpers -------------------------

    ghost function bvadd64(x: bv64, y: bv64): bv64 { x + y }
    ghost function bvadd32(x: bv64, y: bv64): bv64 { low32(x + y) }
    //
    ghost function bvsub64(x: bv64, y: bv64): bv64 { x - y }
    ghost function bvsub32(x: bv64, y: bv64): bv64 { low32(x - y) }
    //
    ghost function bvmul64(x: bv64, y: bv64): bv64 { x * y }
    ghost function bvmul32(x: bv64, y: bv64): bv64 { low32(x * y) }
    
    ghost function bvdiv64(x: bv64, y: bv64): bv64 
    requires y != 0
    { x / y }
    
    ghost function bvdiv32(x: bv64, y: bv64): bv64
    requires low32(y) != 0
    { low32(low32(x) / low32(y)) }
    
    function bvsdiv32(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs32Bit(divisor) != 0x0
    {
        if (dividend & 0x80000000) == (divisor & 0x80000000) then (twocom2Abs32Bit(dividend) / twocom2Abs32Bit(divisor))
        else abs2NegTwocom32Bit((twocom2Abs32Bit(dividend) / twocom2Abs32Bit(divisor)))
    }
    
    function bvsdiv64(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs64Bit(divisor) != 0x0
    {
        if (dividend & 0x8000000000000000) == (divisor & 0x8000000000000000)
            then (twocom2Abs64Bit(dividend) / twocom2Abs64Bit(divisor))
            // Convert dividend and divisor to absolute value and then calculate and then negate the result
            else abs2NegTwocom64Bit(twocom2Abs64Bit(dividend) / twocom2Abs64Bit(divisor))
    }
    
    ghost function bvmod64(x: bv64, y: bv64): bv64
    requires y != 0
    { x % y }
    
    ghost function bvmod32(x: bv64, y: bv64): bv64
    requires low32(y) != 0
    { low32(low32(x) % low32(y)) }
    
    // Signed modulo: a % n = a - n * trunc(a / n)
    function bvsmod64(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs64Bit(divisor) != 0
    {
        dividend - (divisor * bvsdiv64(dividend, divisor))
    }

    function bvsmod32(dividend: bv64, divisor: bv64) :bv64
    requires twocom2Abs32Bit(divisor) != 0x0
    {
        (dividend - (divisor * bvsdiv32(dividend, divisor))) & 0x0000_0000_FFFF_FFFF
    }

    ghost function bvnot64(x: bv64): bv64 { !x }
    ghost function bvnot32(x: bv64): bv64 { low32(!x) }

    ghost function bvor64(x: bv64, y: bv64): bv64 { x | y }
    ghost function bvor32(x: bv64, y: bv64): bv64 { low32(x | y) }

    ghost function bvand64(x: bv64, y: bv64): bv64 { x & y }
    ghost function bvand32(x: bv64, y: bv64): bv64 { low32(x & y) }

    ghost function bvxor64(x: bv64, y: bv64): bv64 { x ^ y }
    ghost function bvxor32(x: bv64, y: bv64): bv64 { low32(x ^ y) }


    ghost function bvlshr32(num: bv64, shift: bv64) : bv64
    {num >> ((shift & 0x1F) as bv5)}

    ghost function bvlshr64(num: bv64, shift: bv64) : bv64
    {num >> ((shift & 0x3F) as bv6)}

    function bvashr32(num: bv64, shift: bv64) :bv64
    {
        if (num & 0x80000000 == 0) then (num >> ((shift & 0x1F) as bv5)) & 0xFFFFFFFF
        else ((num >> ((shift & 0x1F) as bv5)) | !(((0x1 as bv64) << ((32-(shift & 0x1F)) as bv8)) - 0x1)) & 0xFFFFFFFF
    }

    function bvashr64(num: bv64, shift: bv64) :bv64
    {
        if (num & 0x8000000000000000) == 0 then (num >> ((shift & 0x3F) as bv6))
        else ((num >> ((shift & 0x3F) as bv6)) | !(((0x1 as bv64) << ((64-(shift & 0x3F)) as bv8)) - 0x1))
    }

    ghost function bvshl32(num: bv64, shift: bv64) : bv64
    {num << ((shift & 0x1F) as bv5)}

    ghost function bvshl64(num: bv64, shift: bv64) : bv64
    {num << ((shift & 0x3F) as bv6)}

    // ----

    ghost predicate unknown_bool()

    ghost predicate bv_eq(x: bv64, y: bv64) {x == y}

    ghost predicate bv_neq(x: bv64, y: bv64) {x != y}

    ghost predicate is_32bit_zero(x: bv64) {low32(x) == 0}

    ghost predicate not_32bit_zero(x: bv64) {low32(x) != 0}
    
    ghost predicate is_64bit_zero(x: bv64) {x == 0}

    ghost predicate not_64bit_zero(x: bv64) {x != 0}

    ghost predicate bit8signed(val: bv64) {(val & 0x0000000000000080) != 0 }

    ghost predicate bit16signed(val: bv64) {(val & 0x0000000000008000) != 0 }

    ghost predicate bit32signed(val: bv64) {(val & 0x0000000080000000) != 0 }

    function low32(val: bv64) : bv64 {val & 0x0000_0000_FFFF_FFFF}
    
    ghost function low16(val: bv64) : bv64 {val & 0x0000_0000_0000_FFFF}

    ghost function low8(val: bv64) : bv64 {val & 0x0000_0000_0000_00FF}

    ghost function low5(val: bv64) : bv64 {val & 0x0000_0000_0000_001F}

    ghost function low6(val: bv64) : bv64 {val & 0x0000_0000_0000_003F}

    function bv64ToInt64(num: bv64) :int64
    {
        if num & 0x8000_0000_0000_0000 == 0 then (num as int64)
        else -(twocom2Abs64Bit(num) as int64)
    }

    function bv32ToInt32(num: bv64) :int64
    {
        if num & 0x8000_0000 == 0 then ((num & 0x0000_0000_FFFF_FFFF) as int64)
        else -(twocom2Abs32Bit(num) as int64)
    }

    // Flip bits and then add 1, finally remove the sign bit
    function twocom2Abs64Bit(num: bv64) :bv64
    {
        if num & 0x8000000000000000 == 0 then num
        else ((!num) + 1) & 0x7FFF_FFFF_FFFF_FFFF
    }

    // Flip bits and then add 1, finally remove the sign bit
    function twocom2Abs32Bit(num: bv64) :bv64
    {
        if num & 0x80000000 == 0 then num & 0xEFFF_FFFF
        else ((!num) + 1) & 0xEFFF_FFFF
    }

    function abs2NegTwocom32Bit(num: bv64) :bv64
        {
            (((!num) + 1) & 0xFFFFFFFF) | 0x8000_0000
        }

    function abs2NegTwocom64Bit(num: bv64) :bv64
        {
            ((!num) + 1) | 0x8000_0000_0000_0000
        }

    function {:fuel 8} nbytes_wap(num: bv64, N: int) :bv64
    requires N == 2 || N == 4 || N == 8
    {
        byteswap_iter(num, 0, N)
    }

    function {:fuel 8} byteswap_iter(num: bv64, curb: int, N: int) :bv64
    requires 0 <= curb < 8
    requires N == 2 || N == 4 || N == 8
    requires curb < N
    decreases 8-curb
    {
        if curb+1 ==  N then (((num >> (curb * 8)) & 0xff) << ((N-curb-1) * 8))
        else ((((num >> (curb * 8)) & 0xff) << ((N-curb-1) * 8)) | (byteswap_iter(num, curb+1, N)))
    }

    function signext_bits_n2m_low_perf(num:bv64, n: nat, m: nat) : bv64
    requires (n, m) == (8, 32) || (n, m) == (16, 32) ||
             (n, m) == (8, 64) || (n, m) == (16, 64) ||
             (n, m) == (32, 64)
    {
        var sign_bit := (1 << (n-1));
        var bit_n_mask := ((1 << n) -1);
        var ext_sign_bits := 
                !bit_n_mask &
                if m == 32
                then 0x0000_0000_FFFF_FFFF
                else 0xFFFF_FFFF_FFFF_FFFF
                ;

        if (num & sign_bit) != 0
        then (bit_n_mask & num) | ext_sign_bits
        else bit_n_mask & num
    }
    
    ghost function signext_bits_n2m(num:bv64, n: nat, m: nat) : bv64
    requires (n, m) == (8, 32) || (n, m) == (16, 32) ||
             (n, m) == (8, 64) || (n, m) == (16, 64) || (n, m) == (32, 64)
    ensures signext_bits_n2m(num, n, m) == signext_bits_n2m_low_perf(num, n, m)
    {
        match (n, m) {
            case (8, 32) =>
                if bit8signed(num)
                then bvor32(num, 0x00000000FFFFFF00)
                else low8(num)

            case (16, 32) =>
                if bit16signed(num)
                then bvor32(num, 0x00000000FFFF0000)
                else low16(num)

            case (8, 64) =>
                if bit8signed(num)
                then bvor64(num, 0xFFFFFFFFFFFFFF00)
                else low8(num)

            case (16, 64) =>
                if bit16signed(num)
                then bvor64(num, 0xFFFFFFFFFFFF0000)
                else low16(num)

            case (32, 64) =>
                if bit32signed(num)
                then bvor64(num, 0xFFFFFFFF00000000)
                else low32(num)
        }
    }

    lemma signext_two_impls_equal(num:bv64, n: nat, m: nat)
    requires (n, m) == (8, 32) || (n, m) == (16, 32) ||
             (n, m) == (8, 64) || (n, m) == (16, 64) ||
             (n, m) == (32, 64)
    ensures signext_bits_n2m(num, n, m) == signext_bits_n2m_low_perf(num, n, m)
    {}

    ghost function signext_byte_nto8(num:bv64, size: SIZE) : (res: bv64)
    ensures forall i | 0 <= i < size_to_nat(size)
            :: get_nth_byte(res, i) == get_nth_byte(res, i)
    {
        match size {
            case B  => signext_bits_n2m(num, 8, 64)
            case HW => signext_bits_n2m(num, 16, 64)
            case W  => signext_bits_n2m(num, 32, 64)
            case _  => num
        }
    }

    ghost function get_reg_arith_val(s: State, reg: REG) : (res: bv64)
    requires get_reg_typeval(s, reg) != Uninit
    requires valid_etypev_if_ptr(s, get_reg_typeval(s, reg))
    ensures var tv := get_reg_typeval(s, reg);
            is_scalar(tv) ==> (res == tv.val)
    {
        var regtv := get_reg_typeval(s, reg);
        get_arith_val(s, regtv)
    }


    ghost function get_arith_val(s: State, regtv: ETYPEV) : (res: bv64)
    requires regtv != Uninit
    requires valid_etypev_if_ptr(s, regtv)
    ensures is_scalar(regtv) ==> (res == regtv.val)
    {
        match regtv {

            case Scalar(_, val)             => val

            case PtrType(r1, memid1, off1)  => 
                bvadd64(s.mems[r2id(r1)][memid1].base, off1)

            case PtrOrNullType(r2, memid2, off2) => (
                var unknown: bool :| true;
                if unknown
                then bvadd64(s.mems[r2id(r2)][memid2].base, off2)
                else 0
            )
            case _ => (
                assert false;
                -1
            )
        }
    }

    // ------------------------- Memory operation helpers ----------------


    ghost function get_ptr_info(addr_tv: ETYPEV, ioff: s16) : (nat, nat, int)
    requires is_ptr(addr_tv)
    {
        var rid := r2id(addr_tv.r);
        var memid := addr_tv.memid;
            
        var cur_off := 
            if addr_tv.r == PTR_TO_STACK
            then bv64ToInt64(addr_tv.off) + ioff + 512
            else bv64ToInt64(addr_tv.off) + ioff;
        
        (rid, memid, cur_off)
    }

    function size_to_nat(sz: SIZE) : nat
    {
        match sz {
            case B   =>  1
            case HW  =>  2
            case W   =>  4
            case DW  =>  8
        }
    }

    ghost function get_nth_byte(num: bv64, byte_idx:int) : bv64
    requires 0 <= byte_idx < 8
    {
        match byte_idx {

            case 0 => num & 0xff

            case 1 => (num >> 8) & 0xff

            case 2 => (num >> 16) & 0xff

            case 3 => (num >> 24) & 0xff

            case 4 => (num >> 32) & 0xff

            case 5 => (num >> 40) & 0xff

            case 6 => (num >> 48) & 0xff

            case 7 => (num >> 56) & 0xff

            case _ => (
                assert false;
                0
            )
        }
    }

    ghost function low_nsize(val: bv64, size: SIZE) : bv64
    {
        match size {
            case B  => low8(val)
            case HW => low16(val)
            case W  => low32(val)
            case DW => val
        }
    }

    ghost predicate same_type(tv1: ETYPEV, tv2: ETYPEV)
    {
        match (tv1, tv2) {
            case (PtrOrNullType(_, _, _), PtrOrNullType(_, _, _)) => true
            case (PtrType(_, _, _), PtrType(_, _, _)) => true
            case (Scalar(_, _), Scalar(_, _)) => true
            case (Uninit, Uninit) => true
            case _ => false
        }
    }

    predicate all_slots_scalars(slots: seq<MemSlot>)
    {
        forall i | 0 <= i < |slots|
        ::
        is_scalar(slots[i].etypev)
    }

    ghost function etypev_to_val(tv: ETYPEV) : bv64
    requires tv != Uninit
    {
        match tv {
            case Uninit => (
                assert false;
                -1
            )
            case Scalar(_, val) => val
            case PtrType(_, _, off) => off
            case PtrOrNullType(_, _, off) => off
        }
    }

    ghost function read_8_byte_data(data: seq<MemSlot>, alg_off: int) : (res: bv64)
    requires 0 <= alg_off < alg_off + 8 <= |data|
    requires forall i | 0 <= alg_off <= i < alg_off + 8
             ::
             data[i].etypev != Uninit
    {
        ((etypev_to_val(data[alg_off + 0].etypev) & 0xff))        |
        ((etypev_to_val(data[alg_off + 1].etypev) & 0xff) << 8)   |
        ((etypev_to_val(data[alg_off + 2].etypev) & 0xff) << 16)  |
        ((etypev_to_val(data[alg_off + 3].etypev) & 0xff) << 24)  |
        ((etypev_to_val(data[alg_off + 4].etypev) & 0xff) << 32)  |
        ((etypev_to_val(data[alg_off + 5].etypev) & 0xff) << 40)  |
        ((etypev_to_val(data[alg_off + 6].etypev) & 0xff) << 48)  |
        ((etypev_to_val(data[alg_off + 7].etypev) & 0xff) << 56)
    }

    ghost function {:timeLimit 20} read_n_byte_data(
        data: seq<MemSlot>, cur_off: int, size: SIZE, sign_ext: bool
    ) : (res: bv64)
    requires 0 <= cur_off < cur_off + size_to_nat(size) <= |data|
    requires forall i | cur_off <= i < cur_off + size_to_nat(size)
             :: data[i].etypev != Uninit
    {
        match size {
                
            case B  =>
                (etypev_to_val(data[cur_off+0].etypev) & 0xff)
                
            case HW =>
                ((etypev_to_val(data[cur_off+0].etypev) & 0xff))        | 
                ((etypev_to_val(data[cur_off+1].etypev) & 0xff) << 8)
                
            case W  =>
                ((etypev_to_val(data[cur_off+0].etypev) & 0xff))        | 
                ((etypev_to_val(data[cur_off+1].etypev) & 0xff) << 8)   |
                ((etypev_to_val(data[cur_off+2].etypev) & 0xff) << 16)  | 
                ((etypev_to_val(data[cur_off+3].etypev) & 0xff) << 24)
                
            case DW =>
                ((etypev_to_val(data[cur_off].etypev) & 0xff))          |
                ((etypev_to_val(data[cur_off+1].etypev) & 0xff) << 8)   |
                ((etypev_to_val(data[cur_off+2].etypev) & 0xff) << 16)  | 
                ((etypev_to_val(data[cur_off+3].etypev) & 0xff) << 24)  |
                ((etypev_to_val(data[cur_off+4].etypev) & 0xff) << 32)  | 
                ((etypev_to_val(data[cur_off+5].etypev) & 0xff) << 40)  |
                ((etypev_to_val(data[cur_off+6].etypev) & 0xff) << 48)  | 
                ((etypev_to_val(data[cur_off+7].etypev) & 0xff) << 56)
        }
    }

    lemma read_n_byte_data_inv(data: seq<MemSlot>, cur_off: int, size: SIZE)
    requires 0 <= cur_off < cur_off + size_to_nat(size) <= |data|
    requires forall i | 0 <= cur_off <= i < cur_off + size_to_nat(size)
                 ::
                 data[i].etypev != Uninit
    ensures forall i | 0 <= i < size_to_nat(size)
             ::
             get_nth_byte(read_n_byte_data(data, cur_off, size, false), i) == (
                 etypev_to_val(data[cur_off+i].etypev) & 0xff
             )
    {}

    ghost predicate slots_inited(
        s: State, addr_tv: ETYPEV, ioff: s16, size: SIZE
    )
    requires is_ptr(addr_tv) && valid_etypev_if_ptr(s, addr_tv)
    {
        var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);

        var data := s.mems[rid][memid].data;

        forall i | 0 <= cur_off <= i < cur_off + size_to_nat(size)
             ::
             i < |data|
             &&
             data[i].etypev != Uninit
    }

    ghost function {:timeLimit 3} read_n_byte_etypev(
        s: State, addr_tv: ETYPEV,
        ioff: s16, size: SIZE, sign_ext: bool
    ) : (res: ETYPEV)
    requires is_ptr(addr_tv) && valid_etypev_if_ptr(s, addr_tv)
    requires addr_tv.r == PTR_TO_CTX && size == W ==> packet_mems_exist(s)
    requires access_mem_slots_valid(s, addr_tv, ioff, size)
    requires slots_inited(s, addr_tv, ioff, size)
    //
    ensures valid_etypev_if_ptr(s, res)
    {
        var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);

        var data := s.mems[rid][memid].data;
        var mem_type := s.mems[rid][memid].mem_type;
        var slot_1st_tv := data[cur_off].etypev;

        assert {:split_here} true;
        var same_slot := ptr_slots_same_type_perm(data, cur_off, size);

        assert {:split_here} true;
        var nsize_val1 := read_n_byte_data(data, cur_off, size, sign_ext);
        var ext_val1 := if sign_ext
            then signext_byte_nto8(nsize_val1, size)
            else nsize_val1;

        assert {:split_here} true;
        match slot_1st_tv {
                
            case Scalar(k, _) => (
                assert {:split_here} true;
                if addr_tv.r == PTR_TO_CTX && size == W && k == SpecialPtr then
                    if cur_off == 0 || cur_off == 76 then
                        assert packet_mems_exist(s);
                        PtrType(PTR_TO_PACKET_DATA, 0, 0)
                    else if cur_off == 4 || cur_off == 80 then
                        assert packet_mems_exist(s);
                        PtrType(PTR_TO_PACKET_END, 0, 0)
                    else if cur_off == 8 || cur_off == 140 then
                        assert packet_mems_exist(s);
                        PtrType(PTR_TO_PACKET_META, 0, 0)
                    else
                        Scalar(Normal, ext_val1)
                else
                    var new_kind := if same_slot then k else Normal;
                    Scalar(new_kind, ext_val1)
            )

            case PtrType(_, _, _) | PtrOrNullType(_, _, _) => (
                    
                var alg_off := cur_off - (cur_off % 8);
                assert {:split_here} (
                    0 <= alg_off < alg_off + 8 <= |data|
                    &&
                    ptr_slots_same_type_perm(data, cur_off, size)
                    &&
                    forall i | alg_off <= i < alg_off + 8
                    ::
                    ptr_or_ptrornull(data[i].etypev)
                ) by {
                    valid_ptr_slots_implies_8_bytes(s, addr_tv, ioff, size);
                }
                    
                assert {:split_here} true;

                if !same_slot
                then (
                    assert {:split_here} true;
                    assert false;
                    slot_1st_tv // Unreachable
                    
                )
                else (

                    assert {:split_here} true;
                    var val_8b  := read_8_byte_data(data, alg_off);

                    assert {:split_here} true;
                    if size == DW then (
                        if is_ptr(slot_1st_tv)
                        then PtrType(slot_1st_tv.r, slot_1st_tv.memid, val_8b)
                        else PtrOrNullType(
                            slot_1st_tv.r, slot_1st_tv.memid, val_8b
                        )
                        
                    ) else (

                        var rid      := r2id(slot_1st_tv.r);
                        var memid    := slot_1st_tv.memid;

                        assert {:split_here} true;
                        // Pointer absolute value: base + offset
                        var ptr_val := s.mems[rid][memid].base + val_8b;
                        // Read N size and do sign-extension
                        var nsize_val := low_nsize(ptr_val, size);   
                        var ext_val2 := 
                            if sign_ext
                            then signext_byte_nto8(nsize_val, size)
                            else nsize_val;

                        // Final result depens on PtrType or PtrOrNullType
                        assert {:split_here} true;
                        if is_ptr(slot_1st_tv) then (
                            Scalar(Normal, ext_val2)
                        ) else (
                            var unknown: bool :| true;
                            // arith value of null_or_ptr: ptr arith or 0
                            if unknown
                            then Scalar(Normal, ext_val2)
                            else Scalar(Normal, 0)
                        )
                    )
                )
            )

            case Uninit => (
                assert {:split_here} true;
                assert false;
                slot_1st_tv // Unreachable
            )
        }
    }
    
    lemma valid_ptr_slots_implies_8_bytes(
        s: State, addr_tv: ETYPEV, ioff: s16, size: SIZE
    )
    requires is_ptr(addr_tv) && valid_etypev_if_ptr(s, addr_tv)
    requires access_mem_slots_valid(s, addr_tv, ioff, size)
    requires var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);
             var slot_1st_tv := s.mems[rid][memid].data[cur_off].etypev;
             ptr_or_ptrornull(slot_1st_tv)
    //
    ensures var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);
            var data := s.mems[rid][memid].data;
            (
                exists i | cur_off <= i < cur_off + size_to_nat(size)
                ::
                ptr_or_ptrornull(data[i].etypev)
            )
    //
    ensures var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);
            var data := s.mems[rid][memid].data;
            var alg_off := cur_off -(cur_off % 8);
            0 <= alg_off < alg_off + 8 <= |data|
            &&
            (forall i | alg_off <= i < alg_off + 8
            ::
            ptr_or_ptrornull(data[i].etypev)
            )
            &&
            ptr_slots_same_type_perm(data, cur_off, DW)
    {}

    ghost function {:timeLimit 10} reg_to_8byte_data(
        s: State, reg_tv: ETYPEV
    ) : (res: seq<ETYPEV>)
    //
    requires valid_etypev_if_ptr(s, reg_tv)
    requires reg_tv != Uninit
    ensures |res| == 8
    ensures valid_ptr_etypvs(s, res, DW)
    {
        match reg_tv {
            case Scalar(k, v) =>
                [
                    Scalar(k, get_nth_byte(v, 0)),
                    Scalar(k, get_nth_byte(v, 1)),
                    Scalar(k, get_nth_byte(v, 2)),
                    Scalar(k, get_nth_byte(v, 3)),
                    Scalar(k, get_nth_byte(v, 4)),
                    Scalar(k, get_nth_byte(v, 5)),
                    Scalar(k, get_nth_byte(v, 6)),
                    Scalar(k, get_nth_byte(v, 7))
                ]

            case PtrType(r, memid, off) =>
                [
                    PtrType(r, memid, get_nth_byte(off, 0)),
                    PtrType(r, memid, get_nth_byte(off, 1)),
                    PtrType(r, memid, get_nth_byte(off, 2)),
                    PtrType(r, memid, get_nth_byte(off, 3)),
                    PtrType(r, memid, get_nth_byte(off, 4)),
                    PtrType(r, memid, get_nth_byte(off, 5)),
                    PtrType(r, memid, get_nth_byte(off, 6)),
                    PtrType(r, memid, get_nth_byte(off, 7))
                ]

            case PtrOrNullType(r, memid, off) =>
                [
                    PtrOrNullType(r, memid, get_nth_byte(off, 0)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 1)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 2)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 3)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 4)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 5)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 6)),
                    PtrOrNullType(r, memid, get_nth_byte(off, 7))
                ]

            case _ => (
                assert false;
                []
            )

        }
    }

    /* off points to the byte offset of value in tv */
    ghost function {:timeLimit 10} scalar_etypev_to_seq(
        tv: ETYPEV, len: nat, cur_off: nat
    ) :(res: seq<ETYPEV>)
    //
    requires is_scalar(tv)
    requires 0 <= cur_off <= cur_off + len <= 8
    ensures |res| == len
    ensures forall i | 0 <= i < |res| :: is_scalar(res[i])
    {
        match len {
            case 0 => []
            case 1 => [Scalar(tv.kind, get_nth_byte(tv.val, cur_off+0))]
            case 2 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1))
            ]
            case 3 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 2))
            ]
            case 4 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 2)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 3))
            ]
            case 5 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 2)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 3)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 4))
            ]
            case 6 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 2)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 3)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 4)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 5))
            ]
            case 7 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 2)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 3)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 4)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 5)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 6))
            ]
            case 8 => [
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 0)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 1)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 2)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 3)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 4)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 5)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 6)),
                Scalar(tv.kind, get_nth_byte(tv.val, cur_off + 7))
            ]
            case _ => (
                assert false;
                []
            )
        }
    }

    ghost function update_mem_slots(
        s: State, mem_type : MEMTYPE, data: seq<MemSlot>,
        cur_off: int, size: SIZE, new_tvs: seq<ETYPEV>
    ) : (res: seq<MemSlot>)
    //
    requires size_to_nat(size) == |new_tvs|
    requires 0 <= cur_off < cur_off + size_to_nat(size) <= |data|
    requires valid_ptr_etypvs(s, new_tvs, size)
    // Complementary conditions to `valid_ptr_etypvs`
    requires mem_type == RAW ==> (
                forall i | 0 <= i < size_to_nat(size)
                :: !ptr_or_ptrornull(new_tvs[i])
             )
    //
    requires access_slots_valid(s, mem_type, data, cur_off, size)
    //
    // All slots have the same RDWR perm
    // Otherwise, storing a pointer could lead to different byte perms
    requires forall i | cur_off <= i < cur_off + size_to_nat(size)
             :: data[i].field_perm == RDWR
    // If overwrites pointer slots, it must be complete overwrite
    requires ptr_or_ptrornull(data[cur_off].etypev) ==> size == DW
    //
    ensures |data| == |res|
    // Modified slots keeps previous perm and field size
    ensures forall i | 0 <= i < size_to_nat(size)
            ::
            res[cur_off + i].etypev == new_tvs[i]
            &&
            res[cur_off + i].field_perm == data[cur_off + i].field_perm
            &&
            res[cur_off + i].field_size == data[cur_off + i].field_size
            // &&
            // res[cur_off + i].etypev != Uninit
    ensures forall i | 0 <= cur_off <= i < cur_off +size_to_nat(size)
            :: res[i].etypev != Uninit
    // Unmodified slots keep unchanged
    ensures forall j |
            0 <= j < cur_off || cur_off + size_to_nat(size) <= j < |data|
            ::
            res[j] == data[j]
    //
    ensures access_slots_valid(s, mem_type, res, cur_off, size)
    {
        match size {
            
            case B =>
                data[cur_off + 0 := data[cur_off + 0].(etypev := new_tvs[0])]
            
            case HW =>
                data
                [cur_off + 0 := data[cur_off + 0].(etypev := new_tvs[0])]
                [cur_off + 1 := data[cur_off + 1].(etypev := new_tvs[1])]
            
            case W =>
                data
                [cur_off + 0 := data[cur_off + 0].(etypev := new_tvs[0])]
                [cur_off + 1 := data[cur_off + 1].(etypev := new_tvs[1])]
                [cur_off + 2 := data[cur_off + 2].(etypev := new_tvs[2])]
                [cur_off + 3 := data[cur_off + 3].(etypev := new_tvs[3])]
            
            case DW =>
                data
                [cur_off + 0 := data[cur_off + 0].(etypev := new_tvs[0])]
                [cur_off + 1 := data[cur_off + 1].(etypev := new_tvs[1])]
                [cur_off + 2 := data[cur_off + 2].(etypev := new_tvs[2])]
                [cur_off + 3 := data[cur_off + 3].(etypev := new_tvs[3])]
                [cur_off + 4 := data[cur_off + 4].(etypev := new_tvs[4])]
                [cur_off + 5 := data[cur_off + 5].(etypev := new_tvs[5])]
                [cur_off + 6 := data[cur_off + 6].(etypev := new_tvs[6])]
                [cur_off + 7 := data[cur_off + 7].(etypev := new_tvs[7])]
        }
    }

    ghost function update_a_mem_in_state(
        s: State, addr_tv: ETYPEV, new_data: seq<MemSlot>
    ) : (res: State)
    requires is_ptr(addr_tv) && valid_etypev_if_ptr(s, addr_tv)
    {
        var (rid, memid, _) := get_ptr_info(addr_tv, 0);
        s.(mems := (
                s.mems[rid :=
                    s.mems[rid][memid := 
                        s.mems[rid][memid].(data := new_data)
                    ]
                ]
            )
        )
    }

    ghost predicate same_mem_region(s: State, dst: REG, src: REG)
    {
        var dst_tv := get_reg_typeval(s, dst);
        var src_tv := get_reg_typeval(s, src);

        is_ptr(dst_tv) && is_ptr(src_tv)
        &&
        dst_tv == src_tv
        &&
        dst_tv.memid == src_tv.memid
    }

    function {:axiom} sim_concur_mem_val(
        s: State, addr_reg: REG, size: SIZE
    ) : (res: ETYPEV)
    requires mem_inv(s)
    requires is_ptr(get_reg_typeval(s, addr_reg))
    ensures res != Uninit
    ensures size != DW ==> is_scalar(res)
    ensures var (rid, memid, _) :=
            get_ptr_info(get_reg_typeval(s, addr_reg), 0);
            s.mems[rid][memid].mem_type == RAW ==>
                is_scalar(res)
    ensures valid_etypev_if_ptr(s, res)


    lemma {:axiom} axiom_on_concur(
        s1: State, s2: State, addr_reg: REG, size: SIZE
    )
    requires mem_inv(s1)
    requires mem_inv(s2)
    requires is_ptr(get_reg_typeval(s1, addr_reg))
    requires is_ptr(get_reg_typeval(s2, addr_reg))
    requires s1.rand == s2.rand
    ensures sim_concur_mem_val(s1, addr_reg, size) ==
            sim_concur_mem_val(s2, addr_reg, size)


    ghost function get_addr(s: State, reg: REG) : (res: bv64)
    requires var regtv := get_reg_typeval(s, reg);
             ptr_or_ptrornull(regtv) && valid_etypev_if_ptr(s, regtv)
    {
        var regtv := get_reg_typeval(s, reg);

        var (r, memid, off) := (regtv.r, regtv.memid, regtv.off);
        var tid := r2id(regtv.r);
        
        s.mems[tid][memid].base + off
    }

    ghost function get_base_addr(s: State, reg: REG) : (res: bv64)
    requires var regtv := get_reg_typeval(s, reg);
             ptr_or_ptrornull(regtv) && valid_etypev_if_ptr(s, regtv)
    {
        var regtv := get_reg_typeval(s, reg);
        var tid := r2id(regtv.r);
        
        s.mems[tid][regtv.memid].base
    }


    // TODO: enusres are not verified
    function {:axiom} new_base_addr(s: State, t: ETYPEV, size: bv64) : (res: bv64)
    requires ptr_or_ptrornull(t)
    // The memory region does not exist in the s.mems
    requires var (r, memid, off) := (t.r, t.memid, t.off);
             var rid := r2id(t.r);
             (rid >= |s.mems| || (0 <= rid < |s.mems| && memid >= |s.mems[rid]|))
    //
    requires mem_inv(s)
    //
    requires 0 <= r2id(PTR_TO_PACKET_META) < |s.mems|
    requires |s.mems[r2id(PTR_TO_PACKET_META)]| == 1
    requires 0 <= r2id(PTR_TO_PACKET_DATA) < |s.mems|
    requires |s.mems[r2id(PTR_TO_PACKET_DATA)]| == 1
    //
    ensures res != 0
    ensures (
                forall i,j | 0 <= i < |s.mems| && 0 <= j < |s.mems[i]| :: (
                    var base1 := s.mems[i][j].base;
                    var size1 := (|s.mems[i][j].data| as bv64);
                    //
                    // Non-overlapped memory regions
                    base1 != res
                    &&
                    (base1 + size1 <= res  ||  res + size <= base1)
                )
            )
            &&
            (
                t.r == PTR_TO_PACKET_DATA ==> (
                    var base_meta := s.mems[r2id(PTR_TO_PACKET_META)][0].base;
                    var size_meta := (|s.mems[r2id(PTR_TO_PACKET_META)][0].data| as bv64);
                    base_meta + size_meta == res
                )
            )
            &&
            (
                t.r == PTR_TO_PACKET_END ==> (
                    var base_data := s.mems[r2id(PTR_TO_PACKET_DATA)][0].base;
                    var size_data := (|s.mems[r2id(PTR_TO_PACKET_DATA)][0].data| as bv64);
                    base_data + size_data == res
                    &&
                    size == 0
                )
            )
    

    lemma diff_r_diff_id(r1: MemRegion, r2: MemRegion)
    requires r1 != r2
    ensures r2id(r1) != r2id(r2)
    {}

    /*
    lemma diff_base(s: State, reg1: REG, reg2: REG)
    requires (
        var regtv1 := get_reg_typeval(s, reg1);
        var regtv2 := get_reg_typeval(s, reg2);
        
        ptr_or_ptrornull(regtv1)
        &&
        ptr_or_ptrornull(regtv2)
        &&
        (regtv1.r != regtv2.r || regtv1.memid != regtv2.memid)
    )
    requires mem_inv(s)
    ensures get_base_addr(s, reg1) != get_base_addr(s, reg2)
    {
        var regtv1 := get_reg_typeval(s, reg1);
        var regtv2 := get_reg_typeval(s, reg2);

        assert regtv1.r != regtv2.r || regtv1.memid != regtv2.memid;
        
        assert {:split_here} r2id(regtv1.r) != r2id(regtv2.r) || regtv1.memid != regtv2.memid by {
            if regtv1.r != regtv2.r {
                assert {:split_here} r2id(regtv1.r) != r2id(regtv2.r);
            }
            else {
                assert {:split_here} regtv1.memid != regtv2.memid;
            }
        }
        
        assert {:split_here} (r2id(regtv1.r), regtv1.memid) != (r2id(regtv2.r), regtv2.memid);
        
        assert {:split_here} s.mems[r2id(regtv1.r)][regtv1.memid].base != s.mems[r2id(regtv2.r)][regtv2.memid].base;
        
        var b1 := get_base_addr(s, reg1);
        var b2 := get_base_addr(s, reg2);

        assert {:split_here} s.mems[r2id(regtv1.r)][regtv1.memid].base == b1;
        assert {:split_here} s.mems[r2id(regtv2.r)][regtv2.memid].base == b2;

        assert {:split_here} get_base_addr(s, reg1) != get_base_addr(s, reg2) by {
            assert b1 != b2;
        }
    }

    lemma diff_base_2(s: State, r1: nat, memid1: nat, r2: nat, memid2: nat)
    requires mem_inv(s)
    requires r1 != r2 || memid1 != memid2
    requires 0 <= r1 < |s.mems|
    requires 0 <= r2 < |s.mems|
    requires 0 <= memid1 < |s.mems[r1]|
    requires 0 <= memid2 < |s.mems[r2]|
    ensures s.mems[r1][memid1].base != s.mems[r2][memid2].base
    {}
    */

    lemma same_base(s: State, reg1: REG, reg2: REG)
    requires (
        var regtv1 := get_reg_typeval(s, reg1);
        var regtv2 := get_reg_typeval(s, reg2);
        
        ptr_or_ptrornull(regtv1)
        &&
        ptr_or_ptrornull(regtv2)
        &&
        (regtv1.r == regtv2.r && regtv1.memid == regtv2.memid)
    )
    requires mem_inv(s)
    ensures get_base_addr(s, reg1) == get_base_addr(s, reg2)
    {}


    ghost predicate packet_mems_exist(s: State)
    {
        0 <= r2id(PTR_TO_PACKET_META) < |s.mems|
        &&
        0 < |s.mems[r2id(PTR_TO_PACKET_META)]|
        &&
        0 <= r2id(PTR_TO_PACKET_DATA) < |s.mems|
        &&
        0 < |s.mems[r2id(PTR_TO_PACKET_DATA)]|
        &&
        0 <= r2id(PTR_TO_PACKET_END) < |s.mems|
        &&
        0 < |s.mems[r2id(PTR_TO_PACKET_END)]|
    }

    ghost predicate mem_inv(s: State)
    {
        (
            // Memory region size
            forall i, j | 0 <= i < |s.mems| && 0 <= j < |s.mems[i]| ::
                if i == r2id(PTR_TO_PACKET_END)
                then 0 == |s.mems[i][j].data|
                else 0 <= |s.mems[i][j].data| < 0x8000_0000_0000_0000
        )
        &&
        packet_mems_exist(s)
        &&
        (
            // Valid pointer reg
            forall reg :: valid_etypev_if_ptr(s, get_reg_typeval(s, reg))
        )
    }

    ghost predicate access_mem_slots_valid(
        s: State, addr_tv: ETYPEV, ioff: s16, size: SIZE
    )
    requires is_ptr(addr_tv)
    requires valid_etypev_if_ptr(s, addr_tv)
    {
        var (rid, memid, cur_off) := get_ptr_info(addr_tv, ioff);

        var mem := s.mems[rid][memid];

        var mem_type := mem.mem_type;
        var data := mem.data;

        access_slots_valid(s, mem_type, data, cur_off, size)
    }

    ghost predicate access_slots_valid(
        s: State, mem_type: MEMTYPE,
        data: seq<MemSlot>, cur_off: int, size: SIZE
    )
    {
        0 <= cur_off < cur_off + size_to_nat(size) <= |data|
        &&
        // RAW memories are all Scalar(_, _)
        if mem_type == RAW then (
            (s.cfg.strict_alignment ==> cur_off % size_to_nat(size) == 0)
            &&
            (
                forall i| cur_off <= i < cur_off + size_to_nat(size) <= |data|
                ::
                is_scalar(data[i].etypev)
            )
        )
        // STRUCT:  scalars and pointers
        // GENERAL: uninit, scalars, and pointers
        else (
            (cur_off % size_to_nat(size) == 0)
            &&
            (
                var alg_off := cur_off - (cur_off % 8);
                if (
                    exists i | 0 <= alg_off <= i < alg_off + 8
                    ::
                    i < |data|
                    &&
                    ptr_or_ptrornull(data[i].etypev)
                ) then (
                    (cur_off == alg_off)
                    &&
                    0 <= alg_off < alg_off + 8 <= |data|
                    &&
                    // ptr slots have the same type and perm
                    ptr_slots_same_type_perm(data, alg_off, DW)
                    &&
                    // rid and memid in the slots are valid
                    var slot_tv := data[cur_off].etypev;
                    valid_etypev_if_ptr(s, slot_tv)
                ) else (
                    forall i |
                    cur_off <= i < cur_off + size_to_nat(size) <= |data|
                    ::
                    (
                        (mem_type == STRUCT ==> is_scalar(data[i].etypev))
                        &&
                        (mem_type == GENERAL ==>
                            !ptr_or_ptrornull(data[i].etypev))
                    )
                )
            )
        )
    }

    predicate ptr_slots_same_type_perm(
        data: seq<MemSlot>, cur_off: int, size: SIZE
    )
    requires 0 <= cur_off < cur_off + size_to_nat(size) <= |data|
    {
        var sizen := size_to_nat(size);

        match data[cur_off].etypev {
        
            case PtrType     (r0, id0, _) =>
                forall i | cur_off < i < cur_off + sizen ::
                    match data[i].etypev {
                        case PtrType     (r, id, _) =>
                            r == r0 && id == id0
                            &&
                            data[i].field_perm == data[cur_off].field_perm
                        case _  => false
                    }

            case PtrOrNullType(r0, id0, _) =>
                forall i | cur_off < i < cur_off + sizen ::
                    match data[i].etypev {
                        case PtrOrNullType(r, id, _) =>
                            r == r0 && id == id0
                            &&
                            data[i].field_perm == data[cur_off].field_perm
                        case _  => false
                    }
            
            case _ => false
        }
    }
    
    predicate ptr_slots_same_type(tvs: seq<ETYPEV>, cur_off: int, size: SIZE)
    requires 0 <= cur_off < cur_off + size_to_nat(size) <= |tvs|
    {
        var sizen := size_to_nat(size);

        match tvs[cur_off] {
            case PtrType     (r0, id0, _) =>
                forall i | cur_off < i < cur_off + sizen ::
                    match tvs[i] {
                        case PtrType     (r, id, _)  => (r == r0 && id == id0)
                        case _                       => false
                    }
            
            case PtrOrNullType(r0, id0, _) =>
                forall i | cur_off < i < cur_off + sizen ::
                    match tvs[i] {
                        case PtrOrNullType(r, id, _) => (r == r0 && id == id0)
                        case _                       => false
                    }
            
            case _ => false
        }
    }

    predicate valid_ptr_etypvs(s: State, tvs: seq<ETYPEV>, size: SIZE)
    requires |tvs| == size_to_nat(size)
    {
        if size == DW && (
            exists i | 0 <= i < size_to_nat(size)
            ::
            ptr_or_ptrornull(tvs[i])
        ) then (
            // ptr slots have the same type and perm
            ptr_slots_same_type(tvs, 0, size)
            &&
            // rid and memid in the slots are valid
            valid_etypev_if_ptr(s, tvs[0])
        ) else (
            forall i | 0 <= i < size_to_nat(size)
            :: is_scalar(tvs[i])
        )
    }

    predicate valid_etypev_if_ptr(s: State, regtv: ETYPEV) {
        ptr_or_ptrornull(regtv) ==>
            var (r, memid) := (regtv.r, regtv.memid);
             var tid := r2id(regtv.r);
             0 <= tid < |s.mems| && 0 <= memid < |s.mems[tid]|
    }
}
