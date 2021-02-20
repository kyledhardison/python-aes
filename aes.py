
from src.aes_libraries import sbox


# Global Variables
AES_SIZE = 128
BYTE_SIZE = 8


#########################################################################################
# Utility conversion functions
#########################################################################################
def hex_to_int(hex):
    return int(hex, 16)

def bin_to_int(bin):
    return int(bin, 2)

def int_to_bin(num, length):
    return bin(num)[2:].zfill(length)    

def bin_to_array(bin):
    """
    Convert binary string to 4x4 array
    """
    data = [ bin_to_int(bin[i:i+BYTE_SIZE]) for i in range(0, len(bin), BYTE_SIZE) ]
    data = [ data[i:i+4] for i in range(0, len(data), 4)]
    return data

def array_to_bin(array):
    """
    Convert a 4x4 array to a binary string
    """
    out = ""
    for i in range(4):
        for j in range(4):
            out += int_to_bin(array[i][j], BYTE_SIZE)
    return out

def array_to_hex(array):
    """
    Convert a 4x4 array to a hex string
    """
    out = ""
    temp = [[hex(y)[2:] for y in x] for x in array]
    for col in temp:
        out += ''.join(col)
        out += ' '
    return out


#########################################################################################
# AES Functions
#########################################################################################

def add_key(data, subkey):
    """
    XOR data with a given subkey
    """
    return data ^ subkey

def gf_mul(a, b):
    """
    Galois Field multiplication of a given number.

    Taken from an external library.
    """
    if b == 1:
        return a
    tmp = (a << 1) & 0xff
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1b
    if b == 3:
        return gf_mul(a, 2) ^ a

def mix_columns(a, b, c, d):
    """
    Mix the column represented by a, b, c, and d with the gf_mul function
    """
    ret_col = []
    ret_col.append(gf_mul(a, 2) ^ gf_mul(b, 3) ^ gf_mul(c, 1) ^ gf_mul(d, 1))
    ret_col.append(gf_mul(a, 1) ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ gf_mul(d, 1))
    ret_col.append(gf_mul(a, 1) ^ gf_mul(b, 1) ^ gf_mul(c, 2) ^ gf_mul(d, 3))
    ret_col.append(gf_mul(a, 3) ^ gf_mul(b, 1) ^ gf_mul(c, 1) ^ gf_mul(d, 2))

    return ret_col


#########################################################################################
# Main AES Routines
#########################################################################################

def AES_Routine():
    print("Running AES Encryption:")
    with open("data/plaintext.txt", "r") as f:
        plaintext = f.read()

    print("Plaintext input: " + plaintext)

    initial = ""

    # Parse each character into an 8-bit string of 1's and 0's
    for char in plaintext:
        initial += int_to_bin(ord(char), BYTE_SIZE)

    initial = bin_to_int(initial)

    # Read in and parse subkeys
    with open("data/subkey_example.txt", "r") as f:
        subkeys = f.read()

    subkey0, subkey1 = subkeys.split("\n")

    print("Subkeys input: " + subkey0 + ", " + subkey1)
    print()

    subkey0 = hex_to_int(subkey0)
    subkey1 = hex_to_int(subkey1)

    # Run the preliminary addKey() before round 1
    data = add_key(initial, subkey0)

    # Parse to 4x4 array
    data = int_to_bin(data, AES_SIZE)
    data = bin_to_array(data)

    # Perform S-Box substitution on all bytes 
    for i in range(4):
        for j in range(4):
            data[i][j] = sbox.lookup(data[i][j])

    # Perform ShiftRows
    temp = [[], [], [], []]
    for i in range(4):
        temp_row = []
        temp_row.append(data[0][i])
        temp_row.append(data[1][i])
        temp_row.append(data[2][i])
        temp_row.append(data[3][i])
        if i != 0:
            for _ in range(i):
                temp_row.append(temp_row.pop(0))
        temp[0].append(temp_row[0])
        temp[1].append(temp_row[1])
        temp[2].append(temp_row[2])
        temp[3].append(temp_row[3])
    data = temp

    # Perform MixColumns
    temp = [[], [], [], []]
    for i in range(4):
        temp[i] = mix_columns(data[i][0], data[i][1], data[i][2], data[i][3])
    data = temp

    # Perform final AddKey
    data = bin_to_int(array_to_bin(data))
    final = add_key(data, subkey1)
    final= array_to_hex(bin_to_array(int_to_bin(final, AES_SIZE)))

    print("AES Round 1 output:")
    print(final)

    with open("data/result.txt", "w") as f:
        f.write(final)


def subkey_gen():
    print()
    print("Running Subkey Generation:")
    # Read in and parse subkeys
    with open("data/subkey_example.txt", "r") as f:
        subkeys = f.read()

    subkey0 = subkeys.split("\n")[0]

    print("Subkey input: " + subkey0)
    print()

    subkey0 = hex_to_int(subkey0)

    

def main():
    AES_Routine()
    subkey_gen()


if __name__ == "__main__":
    main()
