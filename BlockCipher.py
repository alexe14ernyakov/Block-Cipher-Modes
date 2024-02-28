from enum import Enum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class Mode(Enum):
    ECB = 1
    CBC = 2
    CFB = 3
    OFB = 4
    CTR = 5


class BlockCipher:
    __BLOCK_SIZE = 16

    def __init__(self, key, mode):
        if len(key) != 16:
            raise ValueError("Key length must be 16")

        self.__key = key
        self.__mode = mode

    def __block_cipher_encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.__key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def __block_cipher_decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.__key, AES.MODE_ECB)
        return cipher.decrypt(data)

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
                    data = pad(data, self.__BLOCK_SIZE)

                return self.__block_cipher_encrypt(data)
            case Mode.CBC:
                return b'b'
            case Mode.CFB:
                return b'c'
            case Mode.OFB:
                return b'd'
            case Mode.CTR:
                return b'e'

    def process_block_decrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        match self.__mode:
            case Mode.ECB:
                if is_final_block:
                    data = pad(data, self.__BLOCK_SIZE)

                return self.__block_cipher_decrypt(data)
            case Mode.CBC:
                return b'b'
            case Mode.CFB:
                return b'c'
            case Mode.OFB:
                return b'd'
            case Mode.CTR:
                return b'e'

    def encrypt(self, data: bytes, iv: bytes = None) -> bytes:
        blocks = [data[i:i + self.__BLOCK_SIZE] for i in range(0, len(data), self.__BLOCK_SIZE)]

        ciphertext = b''
        for block in blocks:
            ciphertext = ciphertext + self.process_block_encrypt(block, block == blocks[-1], 'PKCS7')

        return ciphertext

    def decrypt(self, data: bytes, iv: bytes = None) -> bytes:
        blocks = [data[i:i + self.__BLOCK_SIZE] for i in range(0, len(data), self.__BLOCK_SIZE)]

        plaintext = b''
        for block in blocks:
            plaintext = plaintext + self.process_block_decrypt(block, block == blocks[-1], 'PKCS7')

        return plaintext
