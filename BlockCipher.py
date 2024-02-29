import secrets
from enum import Enum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Mode(Enum):
    ECB = 1
    CBC = 2
    CFB = 3
    OFB = 4
    CTR = 5


class BlockCipher:
    __BLOCK_SIZE = 16

    def __init__(self, key, mode):
        if len(key) != self.__BLOCK_SIZE:
            raise ValueError("Key length must be 16")

        self.__key: bytes = key
        self.__mode: Mode  = mode
        self.__iv: bytes = None

    def __block_cipher_encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.__key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def __block_cipher_decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.__key, AES.MODE_ECB)
        return cipher.decrypt(data)

    def __generate_iv(self):
        self.__iv = secrets.token_bytes(self.__BLOCK_SIZE)

    @staticmethod
    def xor(vector1: bytes, vector2: bytes) -> bytes:
        return bytes(b1 ^ b2 for b1, b2 in zip(vector1, vector2))

    def set_key(self, key: bytes):
        if len(key) != 16:
            raise ValueError("Key length must be 16")
        self.__key = key

    def set_mode(self, mode: Mode):
        self.__mode = mode

    def process_block_encrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        match self.__mode:
            case Mode.ECB:
                if is_final_block:
                    data = pad(data, self.__BLOCK_SIZE, padding)

                return self.__block_cipher_encrypt(data)
            case Mode.CBC:
                if is_final_block:
                    data = pad(data, self.__BLOCK_SIZE, padding)

                result = self.__block_cipher_encrypt(self.xor(data, self.__iv))
                self.__iv = result

                return result
            case Mode.CFB:
                cipher = self.__block_cipher_encrypt(self.__iv)

                result = self.xor(cipher, data)
                self.__iv = result

                return result
            case Mode.OFB:
                cipher = self.__block_cipher_encrypt(self.__iv)
                self.__iv = cipher

                result = self.xor(cipher, data)

                return result
            case Mode.CTR:
                cipher = self.__block_cipher_encrypt(self.__iv)
                result = self.xor(cipher, data)

                int_iv = int.from_bytes(self.__iv, byteorder='big')
                int_iv += 1
                self.__iv = int_iv.to_bytes((int_iv.bit_length() + 7) // 8, byteorder='big')

                return result

    def process_block_decrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        match self.__mode:
            case Mode.ECB:
                cipher = self.__block_cipher_decrypt(data)

                if is_final_block:
                    cipher = unpad(cipher, self.__BLOCK_SIZE, padding)

                return cipher
            case Mode.CBC:
                cipher = self.__block_cipher_decrypt(data)

                result = self.xor(cipher, self.__iv)
                self.__iv = data

                if is_final_block:
                    result = unpad(result, self.__BLOCK_SIZE, padding)

                return result
            case Mode.CFB:
                cipher = self.__block_cipher_encrypt(self.__iv)

                result = self.xor(cipher, data)
                self.__iv = data

                return result
            case Mode.OFB:
                cipher = self.__block_cipher_encrypt(self.__iv)
                self.__iv = cipher

                result = self.xor(cipher, data)

                return result
            case Mode.CTR:
                cipher = self.__block_cipher_encrypt(self.__iv)
                result = self.xor(cipher, data)

                int_iv = int.from_bytes(self.__iv, byteorder='big')
                int_iv += 1
                self.__iv = int_iv.to_bytes((int_iv.bit_length() + 7) // 8, byteorder='big')

                return result

    def encrypt(self, data: bytes, iv: bytes = None) -> bytes:
        if iv is not None:
            if len(iv) != self.__BLOCK_SIZE:
                raise ValueError("IV length must be 16")

            self.__iv = iv
        else:
            self.__generate_iv()

        blocks = [data[i:i + self.__BLOCK_SIZE] for i in range(0, len(data), self.__BLOCK_SIZE)]

        ciphertext = b''
        for block in blocks:
            ciphertext = ciphertext + self.process_block_encrypt(block, block == blocks[-1], 'pkcs7')

        return ciphertext

    def decrypt(self, data: bytes, iv: bytes = None) -> bytes:
        if iv is not None:
            if len(iv) != self.__BLOCK_SIZE:
                raise ValueError("IV length must be 16")

            self.__iv = iv
        else:
            self.__generate_iv()

        blocks = [data[i:i + self.__BLOCK_SIZE] for i in range(0, len(data), self.__BLOCK_SIZE)]

        plaintext = b''
        for block in blocks:
            plaintext = plaintext + self.process_block_decrypt(block, block == blocks[-1], 'pkcs7')

        return plaintext
