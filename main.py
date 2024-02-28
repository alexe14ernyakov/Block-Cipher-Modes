from Crypto.Cipher import AES

from BlockCipher import BlockCipher, Mode

if __name__ == '__main__':
    # Task 2.5

    # Task 3
    print('TASK 3')
    hex_key3_1 = '140b41b22a29beb4061bda66b6747e14'
    key3_1 = bytes.fromhex(hex_key3_1)

    hex_ciphertext3_1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
    iv3_1 = bytes.fromhex(hex_ciphertext3_1[0:32])
    ciphertext3_1 = bytes.fromhex(hex_ciphertext3_1[32::])

    cb3_1 = BlockCipher(key3_1, Mode.CBC)

    print('Decrypted ciphertext 1: ', cb3_1.decrypt(ciphertext3_1, iv3_1))
    print()

    # Task 4
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
