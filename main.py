from BlockCipher import BlockCipher, Mode

if __name__ == '__main__':
    b = BlockCipher(b'sixteen-byte-key', Mode.ECB)

    data = b'cryptography-is-my-favorite-subject-in-university'
    b.set_key(b'sixteen-byte-key')
    print(data)

    enc = b.encrypt(data)
    print(enc)

    dec = b.decrypt(enc)
    print(dec)
