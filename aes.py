
from src.aes_libraries import sbox


# Global Variables
AES_SIZE = 128
BYTE_SIZE = 8


# Utility conversion functions
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


def add_key(data, subkey):
    return data ^ subkey


def main():
    with open("data/plaintext.txt", "r") as f:
        plaintext = f.read()

    initial = ""

    # Parse each character into an 8-bit string of 1's and 0's
    for char in plaintext:
        initial += int_to_bin(ord(char), BYTE_SIZE)

    initial = bin_to_int(initial)

    # Read in and parse subkeys
    with open("data/subkey_example.txt", "r") as f:
        subkeys = f.read()

    subkey0, subkey1 = subkeys.split("\n")

    subkey0 = hex_to_int(subkey0)
    subkey1 = hex_to_int(subkey1)

    # Run the preliminary addKey() before round 1
    data = add_key(initial, subkey0)

    # print(bin(initial)[2:].zfill(AES_SIZE))
    # print(bin(subkey0)[2:].zfill(AES_SIZE))
    # print(bin(add_key(initial, subkey0))[2:].zfill(AES_SIZE))

    # Parse to 4x4 array
    data = int_to_bin(data, AES_SIZE)
    data = bin_to_array(data)

    # Perform S-Box substitution on all bytes 
    for i in range(4):
        for j in range(4):
            data[i][j] = sbox.lookup(data[i][j])

    print(data)

    # Perform ShiftRows
    for i in range(4):
        if i != 0:
            for _ in range(i):
                data[i].append(data[i].pop(0))

    print(data)

    # Perform MixColumns
    # https://stackoverflow.com/questions/66115739/aes-mixcolumns-with-python
    # https://medium.com/wavy-engineering/building-aes-128-from-the-ground-up-with-python-8122af44ebf9



if __name__ == "__main__":
    main()
