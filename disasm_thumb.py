from typing import Dict, Iterable, Optional

from intel_hex_tool import Instruction

cond = 'EQ NE CS/HS CC/LO MI PL VS VC HI LS GE LT GT LE AL'.split()
op_prefix_4 = 'ADD EOR LSL LSR ASR ADC SBC ROR TST NEG CMP CMN ORR MUL BIC MVN'.split()
op_prefix_5 = 'STR STRH STRB LDRSB LDR LDRH LDRB LDRSH'.split()


def _reg_list(value: int):
    return ', '.join((f'L{i}' for i in range(8) if (value >> i) & 1))


thumb1_word_ref = {  # NB: Bits go from 15 to 0
    # Table B.5 p643-644 ARM System Developer's Guide
    '000ooiiiiimmmddd': lambda o, i, m, d: f'{["LSL", "LSR", "ASR"][o]} #{i} L{m} L{d}',
    '00011fommmnnnddd': lambda f, o, m, n, d: f'{["ADD", "SUB"][o]} {["L", "#"][f]}{m} L{n} L{d}',
    '001oodddiiiiiiii': lambda o, d, i: f'{["MOV", "CMP", "ADD", "SUB"][o]} L{d} #{i}',
    '010000oooommmddd': lambda o, m, d: f'{op_prefix_4[o]} L{m} L{d}',
    '0100011000mmmddd': lambda m, d: f'CPY R{d}, R{m}',
    '010001o0fgmmmddd': lambda o, f, g, m, d: f'{["ADD", "MOV"][o]} {"LH"[f]}{d}, {"LH"[g]}{m}',
    '01000101fgmmmnnn': lambda f, g, m, n: f'CMP {"LH"[g]}{m}, {"LH"[f]}{n}',
    '01000111ommmm000': lambda o, m: f'B{["", "L"][o]}X R{m}',
    '01001dddiiiiiiii': lambda d, i: f'LDR L{d}. [pc. #{i}*4',
    '0101ooommmnnnddd': lambda o, m, n, d: f'{op_prefix_5[o]} L{m} L{n} L{d}',
    '0110oiiiiinnnddd': lambda o, i, n, d: f'{["ST", "LD"][o]}R L{d}, [L{n}, #{i}*4]',
    '0111oiiiiinnnddd': lambda o, i, n, d: f'{["ST", "LD"][o]}RB L{d}, [L{n}, #{i}]',
    '1110oiiiiinnnddd': lambda o, i, n, d: f'{["ST", "LD"][o]}RH L{d}, [L{n}, #{i}*2]',
    '1001odddiiiiiiii': lambda o, d, i: f'{["ST", "LD"][o]}R L{d}, [sp, #{i}*4',
    '1010odddiiiiiiii': lambda o, d, i: f'ADD L{d}, {["pc", "sp"][o]}, #{i}*4',
    '10110000oiiiiiii': lambda o, i: f'{["ADD", "SUB"][o]} sp, #{i}*4',
    '10110010oommmddd': lambda o, m, d: f'{["SXTH", "SXTB", "UXTH", "UXTB"][o]} L{m} L{d}',
    '10111010oommmddd': lambda o, m, d: f'REV{["", "16", "?", "SH"][o]} L{m} L{d}',
    '1011o10errrrrrrr': lambda o, e, r: f'{["PUSH", "POP"][o]} [{["LR, ", "PC, "][e]}{_reg_list(r)}]',
    '101101100101o000': lambda o: f'SETEND {"LB"[o]}E',
    '10110110011o0aif': lambda o, a, i, f: f'CPSI{"ED"[o]} a={a} i={i} f={f}',
    '10111110iiiiiiii': lambda i: f'BKPT {i}',
    '1100onnnrrrrrrrr': lambda o, n, r: f'{["ST", "LD"][o]}MIA L{n}!, [{_reg_list(r)}]',
    '1101ccccoooooooo': lambda c, o: f'B{cond[c]} offset={o}',
    '11011111iiiiiiii': lambda i: f'SWI {i}',
    '111f0soooooooooo': lambda f, s, o: f'{["B", "BP"][f]} {["offset", "poff"][f]}={["", "-"][s]}{o}',
    '111f1oooooooooo0': lambda f, o: f'BL{["", "X"][f]} offset={o}',
}

thumb2_word_ref = {
    '00oooo': lambda o: 'shift/add/sub/move/cmp',
    '010000': lambda: 'data processing',
    '010001': lambda: 'special + bex',
    '0101oo': lambda: 'load store single item',
    '011ooo': lambda: 'load store single item',
    '100ooo': lambda: 'load store single item',
    '10100o': lambda: 'generate pc relative address',
    '10101o': lambda: 'generate sp relative address',
    '1011xx': lambda: 'misc',
    '11000o': lambda: 'store multiple',
    '11001o': lambda: 'load multiple',
    '1101oo': lambda: 'conditional branch',
    '11100o': lambda: 'unconditional branch',
}


def try_match_word(word: int, pattern: str) -> Optional[Dict[str, int]]:
    args: Dict[str, int] = {}
    value = bin(word)[2:].zfill(len(pattern))
    for p, v in zip(pattern, value):
        if p in '01':
            if p != v:
                return None
        else:
            if p not in args:
                args[p] = 0
            args[p] = args[p] * 2 + int(v)
    return args


def decode_thumb1_chunk(data: bytes, index: int, aligned: bool) -> Instruction:
    left = len(data) - index
    default = Instruction(index, 2 if aligned else 1, '')
    if left < 2:
        return default
    op16 = int.from_bytes(data[index : index + 2], 'little')
    for pattern in thumb1_word_ref:
        args = try_match_word(op16, pattern)
        if args is not None:
            return Instruction(index, 2, thumb1_word_ref[pattern](**args))
    return default


def decode_thumb2_chunk(data: bytes, index: int, aligned: bool) -> Instruction:
    left = len(data) - index
    default = Instruction(index, 2 if aligned else 1, '')
    if left < 2:
        return default
    op16 = int.from_bytes(data[index : index + 2], 'little')
    if op16 >> 11 in {0b11101, 0b11110, 0b11111}:
        # TODO: 32 bit instructions
        pass
    else:
        for pattern in thumb2_word_ref:
            args = try_match_word(op16, pattern)
            if args is not None:
                return Instruction(index, 2, thumb2_word_ref[pattern](**args))
    return default


impls = {
    'thumb-1': decode_thumb1_chunk,
    'thumb-2': decode_thumb2_chunk,
}


def disasm(data: bytes, instructions: str, index: int = 0, aligned: bool = False) -> Iterable[Instruction]:
    while index < len(data):
        chunk = impls[instructions](data, index, aligned)
        index += chunk.len
        yield chunk
