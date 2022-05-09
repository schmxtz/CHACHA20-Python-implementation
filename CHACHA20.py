# Quarterround functions
def rotate_bits(state, offset):
    state_with_leading_zeros = '{:032b}'.format(state)
    return int(state_with_leading_zeros[offset:] + state_with_leading_zeros[:offset], 2)


def add_mod_2_pow32(left_summand, right_summand):
    return (left_summand + right_summand) % 2 ** 32


def bitwise_xor(left_bytes, right_bytes):
    return left_bytes ^ right_bytes


# Constraints
def in_counter_range(counter):
    if -1 >= counter:
        raise ValueError(' Counter must not be negative')
    if counter >= 2 ** 32 - 1:
        raise ValueError('Counter too high')


class CHACHA20:
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        self.state = [0] * 16
        if len(key) != 32:
            raise ValueError('Invalid key length')
        if len(nonce) != 12:
            raise ValueError('Invalid nonce length')
        in_counter_range(counter)
        self.key = key
        self.nonce = nonce
        self.counter = counter

        # Initialize constants
        self.state[0] = 0x61707865
        self.state[1] = 0x3320646e
        self.state[2] = 0x79622d32
        self.state[3] = 0x6b206574

        # Initialize key fields
        for i in range(8):
            self.state[4+i] = int.from_bytes(key[i*4: (i+1)*4], byteorder='little')

        # Initialize counter
        self.state[12] = counter

        #Initialize nonce
        for i in range(3):
            self.state[13 + i] = int.from_bytes(nonce[i*4: (i+1)*4], byteorder='little')


    def qround(self, state: list, a, b, c, d):
        state[a] = add_mod_2_pow32(state[a], state[b])
        state[d] = bitwise_xor(state[d], state[a])
        state[d] = rotate_bits(state[d], 16)

        state[c] = add_mod_2_pow32(state[c], state[d])
        state[b] = bitwise_xor(state[b], state[c])
        state[b] = rotate_bits(state[b], 12)

        state[a] = add_mod_2_pow32(state[a], state[b])
        state[d] = bitwise_xor(state[d], state[a])
        state[d] = rotate_bits(state[d], 8)

        state[c] = add_mod_2_pow32(state[c], state[d])
        state[b] = bitwise_xor(state[b], state[c])
        state[b] = rotate_bits(state[b], 7)

    def inner_block(self, state: list):
            self.qround(state, 0, 4, 8, 12)
            self.qround(state, 1, 5, 9, 13)
            self.qround(state, 2, 6, 10, 14)
            self.qround(state, 3, 7, 11, 15)
            self.qround(state, 0, 5, 10, 15)
            self.qround(state, 1, 6, 11, 12)
            self.qround(state, 2, 7, 8, 13)
            self.qround(state, 3, 4, 9, 14)

    def chacha20_block(self):
        initial_state = self.state.copy()
        for _ in range(10):
            self.inner_block(self.state)
        for i in range(16):
            self.state[i] = add_mod_2_pow32(self.state[i], initial_state[i])
        result = bytes()
        for i in range(16):
            result += int.to_bytes(self.state[i], 4, 'little')
        return result

    def encrypt(self, plaintext: bytes):
        return self.cipher(plaintext)

    def decrypt(self, ciphertext):
        return self.cipher(ciphertext)

    def cipher(self, input_text):
        input_text_length = len(input_text)
        key = self.chacha20_block()
        while len(key) < input_text_length:
            self = CHACHA20(self.key, self.nonce, self.counter + 1)
            key += self.chacha20_block()
        return bytes(a ^ b for a, b in zip(key[:input_text_length], input_text))

