include "types.dfy"

module Terms {

    import opened DataTypes
    
    datatype Instruction =
    //
    | ARITHUNARY(dst: REG, uop: ARITHUNARYOP)
    | ARITHBINREG(dst: REG, src: REG, binop: ARITHBINOP)
    | ARITHBINIMM(dst: REG, src_imm: bv64, binop: ARITHBINOP)
    //
    | DATAMOVIMM(dst: REG, src_imm: bv64, moviop: MOVIMMOP)
    | DATAMOVREG(dst: REG, src: REG, movrop: MOVREGOP)
    //
    | CONDJMPREG(dst: REG, src: REG, jmpop: JMPOP)
    | CONDJMPIMM(dst: REG, src_imm: bv64, jmpop: JMPOP)
    //
    | MEMLD(dst: REG, src:REG, ioff: s16, size: SIZE, sign_ext: bool)
    | MEMSTX(dst: REG, src:REG, ioff: s16, size: SIZE)
    | MEMST(dst: REG, src_imm: bv64, ioff: s16, size: SIZE)
    | ATOMICLS(dst:REG, src:REG, ioff:s16, size: SIZE, op:ATOMICOP)
    //
    | CALL

    datatype REG = 
    | R0
    | R1
    | R2
    | R3
    | R4
    | R5
    | R6
    | R7
    | R8
    | R9
    | R10
    // | Rn

    datatype SIZE =
    | B
    | HW
    | W
    | DW

    datatype ARITHUNARYOP =
    | NEG32
    | BV2BE16
    | BV2BE32
    | BV2LE16
    | BV2LE32
    | BV2SWAP16
    | BV2SWAP32
    | NEG64
    | BV2BE64
    | BV2LE64
    | BV2SWAP64

    datatype ARITHBINOP =
    | ADD32
    | SUB32
    | MUL32
    | DIV32
    | SDIV32
    | MOD32
    | SMOD32
    //
    | BVOR32
    | BVAND32
    | BVXOR32
    | BVLSHR32
    | BVASHR32
    | BVSHL32
    //
    | ADD64
    | SUB64
    | MUL64
    | DIV64
    | SDIV64
    | MOD64
    | SMOD64
    //
    | BVOR64
    | BVAND64
    | BVXOR64
    | BVLSHR64
    | BVASHR64
    | BVSHL64

    datatype MOVIMMOP =
    | MOVIMM32
    | MOVIMM64
    | LOADIMM64
    | LOADMAPFD
    | LOADMAPIDX
    // map_val_by_id
    // var_addr
    // var_addr
    // map_val_by_idxx

    datatype MOVREGOP =
    | MOV32
    | MOVSX8TO32
    | MOVSX16TO32
    | MOV64
    | MOVSX8TO64
    | MOVSX16TO64
    | MOVSX32TO64

    datatype ATOMICOP =
    | ATOMIC_ADD
    | ATOMIC_AND
    | ATOMIC_OR
    | ATOMIC_XOR
    | ATOMIC_FETCH_ADD
    | ATOMIC_FETCH_AND
    | ATOMIC_FETCH_OR
    | ATOMIC_FETCH_XOR
    | ATOMIC_XCHG
    | ATOMIC_CMPXCHG

    datatype JMPOP =
    | JEQ32
    | JNE32
    | JSET32
    | JGT32
    | JGE32
    | JSGT32
    | JSGE32
    | JLT32
    | JLE32
    | JSLT32
    | JSLE32
    //
    | JEQ64
    | JNE64
    | JSET64
    | JGT64
    | JGE64
    | JSGT64
    | JSGE64
    | JLT64
    | JLE64
    | JSLT64
    | JSLE64
}