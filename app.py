from bitarray import bitarray

# Simplified DES algorithm

# -----------------Global variables--------------------- #

# Initial permutation
IP = [1, 5, 2, 0, 3, 7, 4, 6]

# Initial permutation inverse
IPI = [3, 0, 2, 4, 6, 1, 7, 5]

# Expansion permutation
EP = [3, 0, 1, 2, 1, 2, 3, 0]

# P4 permutation
P4 = [1, 3, 2, 0]

# P10 key permutation
P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]

# P8 key permutation
P8 = [5, 2, 6, 3, 7, 4, 9, 8]

# Switch halves
SW = [4, 5, 6, 7, 0, 1, 2, 3]

# S1 box
S0_matrix = [[1, 0, 3, 2],
             [3, 2, 1, 0],
             [0, 2, 1, 3],
             [3, 1, 3, 2]]

# S2 box
S1_matrix = [[0, 1, 2, 3],
             [2, 0, 1, 3],
             [3, 0, 1, 0],
             [2, 1, 0, 3]]

K1 = bitarray()

K2 = bitarray()

left = bitarray()

right = bitarray()

left_c = bitarray()

right_c = bitarray()


# ----------------Permutation functions-------------------- #


# General permutation function used for both message and key.
def perm(b_input, perm_array):
    permutated_msg = bitarray()
    for element in perm_array:
        permutated_msg.append(b_input[element])
    return permutated_msg


# Divide the 8bit array into a 4bit right and 4bit left.
def divide_bitarray(b_input):
    for i in range(4):
        left[i] = b_input[i]
    for i in range(4):
        right[i] = b_input[i+4]


# Divide the 8bit cyphered array into 4bit cyphered right and 4bit cyphered left.
def divide_bitarray_cypher(b_input):
    for i in range(4):
        left_c[i] = b_input[i]
    for i in range(4):
        right_c[i] = b_input[i+4]

# The reason i decided to make 2 separate function for the array division is to be able to change the global values.
# This allows me to be able to access and change them whenever i want.


# ---------------Key functions --------------------------- #
def p10_key_left_shift(b_key):
    # First 5 digits:

    rest = b_key[0]
    for i in range(4):
        b_key[i] = b_key[i+1]
    b_key[4] = rest

    # Last 5 digits:
    rest = b_key[5]
    for i in range(5, 9):
        b_key[i] = b_key[i+1]
    b_key[9] = rest


def p8_key_permutation(b_key, k):
    if k == 1:
        for element in P8:
            K1.append(b_key[element])
    elif k == 2:
        for element in P8:
            K2.append(b_key[element])


def sub_key_generation(b_key):
    key_modified = perm(b_key, P10)
    p10_key_left_shift(key_modified)
    p8_key_permutation(key_modified, 1)

    p10_key_left_shift(key_modified)
    p10_key_left_shift(key_modified)
    p8_key_permutation(key_modified, 2)

# ---------------Helper functions------------------------ #


def bit_to_int(bit_array):
    i = 0
    for bit in bit_array:
        i = (i << 1) | bit
    return i


def xor(b_input, b_key):
    if len(b_input) != len(b_key):
        return -1

    xor_output = b_input
    for i in range(len(b_input)):
        if b_input[i] == b_key[i]:
            xor_output[i] = 0
        else:
            xor_output[i] = 1
    return xor_output


def num_to_binary(number):
    if number == 0:
        return bitarray('00')
    elif number == 1:
        return bitarray('01')
    elif number == 2:
        return bitarray('10')
    elif number == 3:
        return bitarray('11')

# ---------------Encryption/Decryption functions-------------------- #


def sbox(b_input, sbox_m):

    # I know this way is a lot of unnecessary work but i was getting errors trying a more simple approach
    temp_num = [0, 0]
    temp_num[0] = b_input[0]
    temp_num[1] = b_input[3]
    row = bit_to_int(temp_num)
    temp_num[0] = b_input[1]
    temp_num[1] = b_input[2]
    column = bit_to_int(temp_num)
    return num_to_binary(sbox_m[row][column])


# Mapping function
def mapping(bit_input, subkey):

    # Resetting global variables for second mapping call
    # For some reason if i don't reset it then my left value goes from 4 bits to 7 bits
    # I used a lot of print in this function to be able to check for errors in my code
    # I left them like this to show all the operations that are being done and all the values

    global left
    global right
    global left_c
    global right_c
    left = bitarray('0000')
    right = bitarray('0000')
    left_c = bitarray('0000')
    right_c = bitarray('0000')

    divide_bitarray(bit_input)
    print(f'Current left: {left}\n')
    print(f'Current right: {right}\n')
    EP_message = perm(right, EP)
    print(f'Current EP_Message: {EP_message}\n')
    XOR_message = xor(EP_message, subkey)
    print(f'Current XOR_Message: {XOR_message}\n')
    divide_bitarray_cypher(XOR_message)
    print(f'Current left_c: {left_c}\n')
    print(f'Current right_c: {right_c}\n')

    left_cypher = sbox(left_c, S0_matrix)
    right_cypher = sbox(right_c, S1_matrix)
    print(f'Current left_cypher:{left_cypher}\n')
    print(f'Current right_cypher:{right_cypher}\n')
    left_cypher.extend(right_cypher)
    P4_message = perm(left_cypher, P4)
    print(f'Current P4_message: {P4_message}\n')
    return P4_message


# FK function
def fk(bit_input, subkey):
    P4_message = mapping(bit_input, subkey)
    left_xor = xor(left, P4_message)
    left_xor.extend(right)
    return left_xor


# Encrypt function
def encrypt(b_message):
    IP_message = perm(b_message, IP)
    print(f'Current IP_message: {IP_message}\n')
    fk_1 = fk(IP_message, K1)
    SW_message = perm(fk_1, SW)
    print(f'Current SW_message: {SW_message}\n')
    fk_2 = fk(SW_message, K2)
    result = perm(fk_2, IPI)
    return result


# Decrypt function
def decrypt(b_message):
    IP_message = perm(b_message, IP)
    fk_2 = fk(IP_message, K2)
    SW_message = perm(fk_2, SW)
    fk_1 = fk(SW_message, K1)
    result = perm(fk_1, IPI)
    return result

# ---------------------------------------- MAIN Block- --------------------------------------------- #


print('Welcome to my python version of the Simplified Data Encryption Standard (S-DES)')
choice = int(input('For encryption type 1, for decryption type 2: '))
if choice == 1:
    message = input('Please enter an 8-bit number: ')
    while len(message) != 8:
        message = input('Wrong format, enter an 8-bit number. For example 01010101. Your choice:')
    bit_message = bitarray(message)

    key = input('Please enter a 10-bit key:')
    while len(key) != 10:
        key = input('Wrong format, enter a 10-bit key number, For example 0101010101. Your choice:')
    bit_key = bitarray(key)

    print('Commencing key generation:')
    sub_key_generation(bit_key)
    print(f'K1 subkey is {K1}')
    print(f'K2 subkey is {K2}')

    res = encrypt(bit_message)
    print(f'The encrypted message is: {res}\n')
elif choice == 2:
    message = input('Please enter an 8-bit cyphered number: ')
    while len(message) != 8:
        message = input('Wrong format, enter a cyphered 8-bit number. For example 01010101. Your choice:')
    bit_message = bitarray(message)

    key = input('Please enter a 10-bit key:')
    while len(key) != 10:
        key = input('Wrong format, enter a 10-bit key number, For example 0101010101. Your choice:')
    bit_key = bitarray(key)

    print('Commencing key generation:')
    sub_key_generation(bit_key)
    print(f'K1 subkey is {K1}')
    print(f'K2 subkey is {K2}')

    res = decrypt(bit_message)
    print(f'The original message was: {res}\n')

