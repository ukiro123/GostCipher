import sys

def GOST_28147(to, mode, key256b, from_data, length):
    length = length if length % 8 == 0 else length + (8 - (length % 8))
    keys32b = split_256bits_to_32bits(key256b)
    for i in range(0, length, 8):
        N1, N2 = split_64bits_to_32bits(join_8bits_to_64bits(from_data[i:i+8]))
        feistel_cipher(mode, N1, N2, keys32b)
        to[i:i+8] = split_64bits_to_8bits(join_32bits_to_64bits(N1, N2))
    return length

def feistel_cipher(mode, block32b_1, block32b_2, keys32b):
    if mode in ['E', 'e']:
        for round in range(24):
            round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round)
        for round in range(31, 23, -1):
            round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round)
    elif mode in ['D', 'd']:
        for round in range(8):
            round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round)
        for round in range(31, 7, -1):
            round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round)

def round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round):
    result_of_iter = (block32b_1 + keys32b[round % 8]) % (2**32)
    result_of_iter = substitution_table(result_of_iter, round % 8)
    result_of_iter = LSHIFT_nBIT(result_of_iter, 11, 32)
    block32b_1, block32b_2 = block32b_2, result_of_iter ^ block32b_2

def substitution_table(block32b, sbox_row):
    blocks4b = split_32bits_to_8bits(block32b)
    substitution_table_by_4bits(blocks4b, sbox_row)
    return join_4bits_to_32bits(blocks4b)

def substitution_table_by_4bits(blocks4b, sbox_row):
    for i in range(4):
        block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F]
        block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4]
        blocks4b[i] = (block4b_2 << 4) | block4b_1

def split_256bits_to_32bits(key256b):
    keys32b = []
    for i in range(0, 32, 4):
        keys32b.append(int.from_bytes(key256b[i:i+4], 'big'))
    return keys32b

def split_64bits_to_32bits(block64b):
    return (block64b >> 32) & 0xFFFFFFFF, block64b & 0xFFFFFFFF

def split_64bits_to_8bits(block64b):
    return [(block64b >> (56 - i*8)) & 0xFF for i in range(8)]

def split_32bits_to_8bits(block32b):
    return [(block32b >> (24 - i*8)) & 0xFF for i in range(4)]

def join_32bits_to_64bits(block32b_1, block32b_2):
    return (block32b_1 << 32) | block32b_2

def join_8bits_to_64bits(blocks8b):
    return int.from_bytes(blocks8b, 'big')

def join_4bits_to_32bits(blocks4b):
    return int.from_bytes(blocks4b, 'big')

def print_array(array):
    print("[", end=" ")
    for i in array:
        print(i, end=" ")
    print("]")

def print_bits(x, Nbit):
    for i in range(Nbit-1, -1, -1):
        print(1 if x & (1 << i) else 0, end="")
    print()

Sbox = [
    [0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3],
    [0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1],
    [0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2],
    [0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8],
    [0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1],
    [0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6],
    [0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7],
    [0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE]
]

def LSHIFT_nBIT(x, L, N):
    return ((x << L) | (x >> (-L & (N - 1)))) & ((1 << N) - 1)

def main():
    encrypted = bytearray()
    decrypted = bytearray()
    key256b = b"this_is_a_pasw_for_GOST_28147_89"

    buffer = bytearray()
    position = 0
    while True:
        ch = sys.stdin.read(1)
        if ch == '\n' or position >= 1023:
            break
        buffer.append(ord(ch))
        position += 1

    print("Open message:")
    print(buffer.decode())
    print()

    position = GOST_28147(encrypted, ord('E'), key256b, buffer, position)
    print("Encrypted message:")
    print_array(encrypted)
    print()

    print("Decrypted message:")
    position = GOST_28147(decrypted, ord('D'), key256b, encrypted, position)
    print_array(decrypted)
    print(decrypted.decode())
    print()

if __name__ == "__main__":
    main()