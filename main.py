from BlockCipher import BlockCipher, Mode
from Crypto.Cipher import AES


def task3():
    print('TASK 3')
    hex_key3_1 = '140b41b22a29beb4061bda66b6747e14'
    key3_1 = bytes.fromhex(hex_key3_1)

    hex_ciphertext3_1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
    iv3_1 = bytes.fromhex(hex_ciphertext3_1[0:32])
    ciphertext3_1 = bytes.fromhex(hex_ciphertext3_1[32::])

    cb3_1 = BlockCipher(key3_1, Mode.CBC)

    print('Decrypted ciphertext 1: ', cb3_1.decrypt(ciphertext3_1, iv3_1))
    print()

    hex_key3_2 = '140b41b22a29beb4061bda66b6747e14'
    key3_2 = bytes.fromhex(hex_key3_2)

    hex_ciphertext3_2 = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
    iv3_2 = bytes.fromhex(hex_ciphertext3_2[0:32])
    ciphertext3_2 = bytes.fromhex(hex_ciphertext3_2[32::])

    cb3_2 = BlockCipher(key3_2, Mode.CBC)

    print('Decrypted ciphertext 2: ', cb3_2.decrypt(ciphertext3_2, iv3_2))
    print()

    hex_key3_3 = '36f18357be4dbd77f050515c73fcf9f2'
    key3_3 = bytes.fromhex(hex_key3_3)

    hex_ciphertext3_3 = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
    iv3_3 = bytes.fromhex(hex_ciphertext3_3[0:32])
    ciphertext3_3 = bytes.fromhex(hex_ciphertext3_3[32::])

    cb3_3 = BlockCipher(key3_3, Mode.CTR)

    print('Decrypted ciphertext 3: ', cb3_3.decrypt(ciphertext3_3, iv3_3))
    print()


def task4():
    print('TASK 4')
    text = b'text-consisting-of-two-and-a-half-blocks'
    custom_iv = b'sixteen-bytes-iv'

    bc4_1 = BlockCipher(b'sixteen-byte-key', Mode.ECB)
    print('Plaintext:               ', text, '; length: ', len(text))
    encrypted_text4_1 = bc4_1.encrypt(text)
    print('Encrypted text with ECB: ', encrypted_text4_1, '; length: ', len(encrypted_text4_1))
    decrypted_text4_1 = bc4_1.decrypt(encrypted_text4_1)
    print('Decrypted text with ECB: ', decrypted_text4_1, '; length: ', len(decrypted_text4_1))
    print()

    bc4_2 = BlockCipher(b'sixteen-byte-key', Mode.CBC)
    print('Plaintext:               ', text, '; length: ', len(text))
    encrypted_text4_2 = bc4_2.encrypt(text, custom_iv)
    print('Encrypted text with CBC: ', encrypted_text4_2, '; length: ', len(encrypted_text4_2))
    decrypted_text4_2 = bc4_2.decrypt(encrypted_text4_2, custom_iv)
    print('Decrypted text with CBC: ', decrypted_text4_2, '; length: ', len(decrypted_text4_2))
    print()

    bc4_3 = BlockCipher(b'sixteen-byte-key', Mode.CFB)
    print('Plaintext:               ', text, '; length: ', len(text))
    encrypted_text4_3 = bc4_3.encrypt(text, custom_iv)
    print('Encrypted text with CFB: ', encrypted_text4_3, '; length: ', len(encrypted_text4_3))
    decrypted_text4_3 = bc4_3.decrypt(encrypted_text4_3, custom_iv)
    print('Decrypted text with CFB: ', decrypted_text4_3, '; length: ', len(decrypted_text4_3))
    print()

    bc4_4 = BlockCipher(b'sixteen-byte-key', Mode.OFB)
    print('Plaintext:               ', text, '; length: ', len(text))
    encrypted_text4_4 = bc4_4.encrypt(text, custom_iv)
    print('Encrypted text with OFB: ', encrypted_text4_4, '; length: ', len(encrypted_text4_4))
    decrypted_text4_4 = bc4_4.decrypt(encrypted_text4_4, custom_iv)
    print('Decrypted text with OFB: ', decrypted_text4_4, '; length: ', len(decrypted_text4_4))
    print()

    bc4_5 = BlockCipher(b'sixteen-byte-key', Mode.CTR)
    print('Plaintext:               ', text, '; length: ', len(text))
    encrypted_text4_5 = bc4_5.encrypt(text, custom_iv)
    print('Encrypted text with CTR: ', encrypted_text4_5, '; length: ', len(encrypted_text4_5))
    decrypted_text4_5 = bc4_5.decrypt(encrypted_text4_5, custom_iv)
    print('Decrypted text with CTR: ', decrypted_text4_5, '; length: ', len(decrypted_text4_5))
    print()


def main():
    task3()
    task4()

    return 0


if __name__ == '__main__':
    main()
