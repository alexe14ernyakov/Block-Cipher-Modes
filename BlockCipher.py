from enum import Enum
from Crypto.Cipher import AES


class Mode(Enum):
    ECB = 1
    CBC = 2
    CFB = 3
    OFB = 4
    CTR = 5


class BlockCipher:
    def __init__(self, key, mode):
        if len(key) != 16:
            raise ValueError("Key length must be 16")

        self.__key = key
        self.__mode = mode

    @staticmethod
    def __block_cipher_encrypt(data: bytes) -> bytes:
        cipher = AES.new(data, AES.MODE_ECB)
        return cipher.encrypt(data).hex()

    @staticmethod
    def __block_cipher_decrypt(data: bytes) -> bytes:
        cipher = AES.new(data, AES.MODE_ECB)
        return cipher.decrypt(data).hex()

    def set_key(self, key: bytes):
        if len(key) != 16:
            raise ValueError("Key length must be 16")
        self.__key = key

    def set_mode(self, mode: Mode):
        self.__mode = mode

    def process_block_encrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        pass

    def process_block_decrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        pass

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        pass

    def decrypt(self, data: bytes) -> bytes:
        pass
