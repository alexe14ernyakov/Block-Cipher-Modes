from Crypto.Cipher import AES

from BlockCipher import BlockCipher, Mode

if __name__ == '__main__':
    b = BlockCipher(b'sixteen-byte-key', Mode.CBC)

    byte1 = b'\x01\x02\x03\x04'
    byte2 = b'\x05\x06\x13\x08'
    print(BlockCipher.xor(byte1, byte2))

    data = b'cryptography-is-my-favorite-subject-in-university'
    b.set_key(b'sixteen-byte-key')
    print(data, len(data))

    enc = b.encrypt(data)
    print(enc, len(enc))

    dec = b.decrypt(enc)
    print(dec, len(dec))
