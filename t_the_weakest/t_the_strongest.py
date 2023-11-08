from capstone import *
from pprint import pprint
import sys
import os

VERBOSE = False

"""T the weakest"""
"""EN Description
T「AHHHHHH!」 S「LOOKS LIKE T IS DEFEATED」 G「HEH. HE'S ALWAYS THE WEAKEST OF THE BIG ONE HUNDRED.」 C「LOSING TO A MERE MORTAL. WHAT A DISGRANCE TO TSG-ER.」
"""
"""JP Description
T「グアアアア」 S「Tがやられたようだな…」 G「フフフ…奴は百天王の中でも最弱…」 C「人間ごときに負けるとはTSGerの面汚しよ…」
"""

def xtract(input_bytes: bytes, multiplier: int, addend: int, modulo: int, seed: int):
    # Not underflow
    overflowFix = lambda x, b: int(hex(x)[2:][-(b * 2):], 16)
    # Very interesting cipher
    # Starting state
    # edx = 0x54
    # out = []
    # for ch in clone:
    #     # imul rax, rdx, 0x105c6148
    #     mul = edx * 0x105c6148
    #     # Overflow fix (a long long)
    #     mul = overflowFix(mul, 8)
    #     # add rax, 0x265a4961
    #     add = mul + 0x265a4961
    #     # cqo
    #     # idv rsi
    #     edx = add % 0x3b9acb5d
    #     cip = edx & 0xff
    #     out.append(cip ^ ch)
    # out = bytes(out)
    edx = seed
    out = bytes([ch ^ (0xff & (edx := (overflowFix(edx * multiplier, 8) + addend) % modulo)) for ch in input_bytes])
    return out

md = Cs(CS_ARCH_X86, CS_MODE_64)

def disassemble_till_mnemonic(code_section: bytes, stop_mnemonic: str, base: int = 0x1000):
    for (address, size, mnemonic, op_str) in md.disasm_lite(code_section, base):
        yield (address, mnemonic, op_str, size)
        if mnemonic == stop_mnemonic:
            break


def harvest(code_section: bytes):
    """Detect cipher from the program
    code_section should be base+0x1000 or similar
    """

    # data is always at offset 2018
    # the size is tricky to get
    #     In the main function a rep movs (f3 a4) is used to copy data, and before that there is always `mov ecx, length`
    #         main+0x2a                b953c01200             mov ecx, data.0012c053 ; 0x12c053
    #         main+0x2f                4c8d64242d             lea r12, [rsp + 0x2d]
    #         main+0x34                8a00                   mov al, byte [rax]
    #         main+0x36                f3a4                   rep movsb byte [rdi], byte ptr [rsi]
    #     We will search for the instruction
    # We also need to know the multiplier, addend, and modulo
    #     Since div works on two quadword, it needs to convert using cqo (48 99)
    #     For example, in the given binary:
    #         main+0x44                be5dcb9a3b             mov esi, 0x3b9acb5d
    #         main+0x49                488dbc2480c01200       lea rdi, [rsp + 0x12c080]
    #         main+0x51                4869c248615c10         imul rax, rdx, 0x105c6148
    #         main+0x58                480561495a26           add rax, 0x265a4961
    #         main+0x5e                4899                   cqo
    #     We can trace up 4 instructions to get all those values :)
    # How does this program check key? The condition is between copying operation and decryptin operation
    # We know the addresses for both of them, so we can disassemble them using capstone

    # There are four types of checking flag/seed, with consistent pattern
    # 1: Direct assignment - We simply copy the value from src
    #     mov edx, expect
    # 2: Double modulo - We acquire two modulo ops and their expected result
    # [x for x in range(0xff) if x % 0xd == 0x7 and x % 0x29 == 0x1d]
    #     idiv denom1
    #     cmp ..., expect1 / dec ... 
    #     idiv denom2
    #     cmp ..., expect2 / dec ... 
    # 3: Xorshift32 (but the register size is 64) - We find the final result of this by looking at the cmp at the end
    # [x for x in range(0xff) for y in [(x << 0xd) ^ x] for z in [(y >> 0x11) ^ y] if z ^ (z << 5) == 0x104687]
    #     shl ..., 0xd
    #     shr ..., 0x11
    #     shl ..., 0x5
    #     cmp ..., expect
    # 4: Multiplication OR - We find the factor that has pattern (... - hex) where hex is within range [0x20, 0x7f]
    #     lea     rax, [rdx - 0x5f]
    #     lea     rcx, [rdx + 0xe]
    #     imul    rax, rcx
    #     lea     rcx, [rdx + 0x8a]
    #     imul    rax, rcx
    #     lea     rcx, [rdx - 0x97]
    #     imul    rax, rcx
    #     lea     rcx, [rdx - 0xb4]
    #     imul    rax, rcx
    #     test    rax, rax

    # Disassemble of `main`
    main_dism = [i for i in disassemble_till_mnemonic(code_section[0xA0:], 'ret', 0x10A0)]
    
    # def type4_checker(indexed_disassembled_code: Tuple[int, Tuple[int, str, str]]):
    #     for idx, i in reversed(indexed_disassembled_code):
    #         if idx > 0 and i[1] == "test" and main_dism[idx - 1][1] == "imul"
        
    if VERBOSE:
        pprint(main_dism)

    i_get_op = lambda i, n: i[2].split(", ")[n]
    get_op = lambda _idx, n: i_get_op(main_dism[_idx], n)
    get_op_as_int = lambda _idx, n: int(get_op(_idx, n), 16)
    unbracket = lambda s: s[1:-1]
    
    # Search for rep movsb
    copy_op_idx = -1
    for idx, i in enumerate(main_dism):
        if i[1] == 'rep movsb':
            copy_op_idx = idx
            break
    assert copy_op_idx != -1, f"Cannot find rep"
    print(f"Found rep: {main_dism[copy_op_idx]}")
    # Reading size
    size_set_idx = -1
    for idx, i in reversed(list(enumerate(main_dism[:copy_op_idx]))):
        if i[1] == 'mov' and i_get_op(i, 0) == "ecx":
            size_set_idx = idx
            break
    assert size_set_idx != -1, f"Cannot find size"
    print(f"Found size: {main_dism[size_set_idx]}")
    size = get_op_as_int(size_set_idx, -1)
    # Reading starting address
    # From 22nd layer, the base address for data is changed, so we have to find and parse it
    data_addr_idx = -1
    for idx, i in reversed(list(enumerate(main_dism[:copy_op_idx]))):
        if i[1] == 'lea' and i_get_op(i, 0) == "rsi":
            data_addr_idx = idx
            break
    assert data_addr_idx != -1, f"Cannot find data address"
    print(f"Found base address: {main_dism[data_addr_idx]}")
    data_addr = int(unbracket(get_op(data_addr_idx, -1)).split(' + ')[-1], 16) + i[3] + i[0]

    # Search for cqo
    cqo_idx = -1
    for idx, i in list(enumerate(main_dism))[copy_op_idx:]:
        if i[1] == 'cqo':
            cqo_idx = idx
            break
    assert cqo_idx != -1, f"Cannot find cqo"
    print(f"Found cqo: {main_dism[cqo_idx]}")
    # Sample size based on above code
    modulo_idx = -1
    multiplier_idx = -1
    addend_idx = -1
    for idx, i in reversed(list(enumerate(main_dism[:cqo_idx]))):
        # print(idx, i, i_get_op(i, 0))
        if i[1] == 'mov' and i_get_op(i, 0) == "esi" and modulo_idx == -1:
            print(f"Found modulo: {i}")
            modulo_idx = idx
        if i[1] == 'imul' and multiplier_idx == -1:
            print(f"Found multiplier: {i}")
            multiplier_idx = idx
        if i[1] == 'add' and addend_idx == -1:
            print(f"Found addend: {i}")
            addend_idx = idx
        if modulo_idx != -1 and multiplier_idx != -1 and addend_idx != -1:
            break
    assert modulo_idx != -1, f"Cannot find modulo"
    assert multiplier_idx != -1, f"Cannot find multiplier"
    assert addend_idx != -1, f"Cannot find addend"
    modulo = get_op_as_int(modulo_idx, -1)
    multiplier = get_op_as_int(multiplier_idx, -1)
    addend = get_op_as_int(addend_idx, -1)
    
    return {"addr": data_addr, "size": size, "modulo": modulo, "multiplier": multiplier, "addend": addend}


if __name__=="__main__":
    # argv = sys.args
    # main(argv[0], argv[1])
    if "-v" in sys.argv:
        VERBOSE = True

    # with open("data2018", "rb") as fd:
    #     data2018 = fd.read()
    # with open("data2018.elf", "wb") as fd:
    #     fd.write(xtract(data2018, 0x105c6148, 0x265a4961, 0x3b9acb5d))

    # We don't always know the starting value, so I will verbosively disassemble
    _fname = "t_the_weakest"
    fname = _fname
    stage = 0
    seed_col = []
    
    if os.path.isfile("flag"):
        with open("flag", "rb") as fd:
            seed_col = list(fd.read())
        print("Found recorded process", seed_col)
    is_byte_loaded = False
    while True:
        print("Stage", stage)
        if not is_byte_loaded:
            with open(fname, "rb") as fd:
                raw = fd.read()
        else:
            raw = extracted_data
        
        is_pre_solved = stage < len(seed_col)
        param = harvest(raw[0x1000:])
        encrypted_data = raw[param["addr"]:][:param["size"]]

        if is_pre_solved:
            seed = seed_col[stage]
        else:
            # Need human assistant
            # This can be automated by symbolic execution, but I'm lazy :p
            # Here, I also assume the address `main` to be 0x10A0 which I later know to be wrong.
            # In some cases, like 22nd layer, it is supposed to start at 0x10B0. Luckily, the disassembler still works
            for address, mnemonic, op_str, _ in disassemble_till_mnemonic(raw[0x10A0:], 'ret', 0x10A0):
                print("%x:\t%s\t%s" % (address, mnemonic, op_str))
            seed = input("Please input seed (hex):")
            seed = int(seed, 16)
            seed_col.append(seed)
            with open("flag", "wb") as fd:
                fd.write(bytes(seed_col))
        
        extracted_data = xtract(encrypted_data, param["multiplier"], param["addend"], param["modulo"], seed)

        fname = _fname + f"_p{stage}"
        if not os.path.isfile(fname):
            # We did not load them from disk, so let's save backup to disk
            with open(fname, "wb") as fd:
                fd.write(extracted_data)
        stage += 1
