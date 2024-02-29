from BlockCipher import BlockCipher, Mode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def task2_5():
    BLOCK_SIZE = 16
    plaintext = b'message-for-first-task'
    key2 = b'sixteen-byte-key'
    custom_iv = b'sixteen-bytes-iv'

    bc2 = BlockCipher(key2, Mode.CBC)
    cipher = AES.new(key2, AES.MODE_CBC, custom_iv)

    print(f'Plaintext:                       {plaintext}')
    encrypted2_1 = bc2.encrypt(plaintext, custom_iv)
    print(f'Encrypted text with my own CBC:  {encrypted2_1}')
    decrypted2_1 = cipher.decrypt(encrypted2_1)
    print(f'Decrypted text with library CBC: {unpad(decrypted2_1, BLOCK_SIZE)}\n')

    cipher = AES.new(key2, AES.MODE_CBC, custom_iv)

    print(f'Plaintext:                       {plaintext}')
    encrypted2_1 = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    print(f'Encrypted text with library CBC: {encrypted2_1}')
    decrypted2_1 = bc2.decrypt(encrypted2_1, custom_iv)
    print(f'Decrypted text with my own CBC:  {decrypted2_1}\n')


def task3():
    BLOCK_SIZE = 16

    cbc_hex_key = '140b41b22a29beb4061bda66b6747e14'
    hex_ciphertext3_1 = '''4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee
                           2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'''

    cbc_key = bytes.fromhex(cbc_hex_key)
    iv3_1 = bytes.fromhex(hex_ciphertext3_1[0:2*BLOCK_SIZE])
    ciphertext3_1 = bytes.fromhex(hex_ciphertext3_1[2*BLOCK_SIZE::])

    cb3_1 = BlockCipher(cbc_key, Mode.CBC)
    print(f'Decrypted ciphertext 1: {cb3_1.decrypt(ciphertext3_1, iv3_1)}')

    hex_ciphertext3_2 = '''5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48
                           e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'''

    iv3_2 = bytes.fromhex(hex_ciphertext3_2[0:2*BLOCK_SIZE])
    ciphertext3_2 = bytes.fromhex(hex_ciphertext3_2[2*BLOCK_SIZE::])

    cb3_2 = BlockCipher(cbc_key, Mode.CBC)
    print(f'Decrypted ciphertext 2: {cb3_2.decrypt(ciphertext3_2, iv3_2)}')

    ctr_hex_key = '36f18357be4dbd77f050515c73fcf9f2'
    hex_ciphertext3_3 = '''69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb505
                           4dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'''

    ctr_key = bytes.fromhex(ctr_hex_key)
    iv3_3 = bytes.fromhex(hex_ciphertext3_3[0:2*BLOCK_SIZE])
    ciphertext3_3 = bytes.fromhex(hex_ciphertext3_3[2*BLOCK_SIZE::])

    cb3_3 = BlockCipher(ctr_key, Mode.CTR)
    print(f'Decrypted ciphertext 3: {cb3_3.decrypt(ciphertext3_3, iv3_3)}')

    hex_ciphertext3_4 = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'

    iv3_4 = bytes.fromhex(hex_ciphertext3_4[0:2*BLOCK_SIZE])
    ciphertext3_4 = bytes.fromhex(hex_ciphertext3_4[2*BLOCK_SIZE::])

    cb3_4 = BlockCipher(ctr_key, Mode.CTR)

    print(f'Decrypted ciphertext 4: {cb3_4.decrypt(ciphertext3_4, iv3_4)}\n')


def task4():
    plaintext = b'text-consisting-of-two-and-a-half-blocks'
    custom_iv = b'sixteen-bytes-iv'
    key4 = b'sixteen-byte-key'

    bc4_1 = BlockCipher(key4, Mode.ECB)
    print(f'Plaintext:               {plaintext}')
    encrypted_text4_1 = bc4_1.encrypt(plaintext)
    print(f'Encrypted text with ECB: {encrypted_text4_1}')
    decrypted_text4_1 = bc4_1.decrypt(encrypted_text4_1)
    print(f'Decrypted text with ECB: {decrypted_text4_1}\n')

    bc4_2 = BlockCipher(key4, Mode.CBC)
    print(f'Plaintext:               {plaintext}')
    encrypted_text4_2 = bc4_2.encrypt(plaintext, custom_iv)
    print(f'Encrypted text with CBC: {encrypted_text4_2}')
    decrypted_text4_2 = bc4_2.decrypt(encrypted_text4_2, custom_iv)
    print(f'Decrypted text with CBC: {decrypted_text4_2}\n')

    bc4_3 = BlockCipher(key4, Mode.CFB)
    print(f'Plaintext:               {plaintext}')
    encrypted_text4_3 = bc4_3.encrypt(plaintext, custom_iv)
    print(f'Encrypted text with CFB: {encrypted_text4_3}')
    decrypted_text4_3 = bc4_3.decrypt(encrypted_text4_3, custom_iv)
    print(f'Decrypted text with CFB: {decrypted_text4_3}\n')

    bc4_4 = BlockCipher(key4, Mode.OFB)
    print(f'Plaintext:               {plaintext}')
    encrypted_text4_4 = bc4_4.encrypt(plaintext, custom_iv)
    print(f'Encrypted text with OFB: {encrypted_text4_4}')
    decrypted_text4_4 = bc4_4.decrypt(encrypted_text4_4, custom_iv)
    print(f'Decrypted text with OFB: {decrypted_text4_4}\n')

    bc4_5 = BlockCipher(key4, Mode.CTR)
    print(f'Plaintext:               {plaintext}')
    encrypted_text4_5 = bc4_5.encrypt(plaintext, custom_iv)
    print(f'Encrypted text with CTR: {encrypted_text4_5}')
    decrypted_text4_5 = bc4_5.decrypt(encrypted_text4_5, custom_iv)
    print(f'Decrypted text with CTR: {decrypted_text4_5}\n')


def main():
    print('TASK 2.5')
    task2_5()

    print('TASK 3')
    task3()

    print('TASK 4')
    task4()

    return 0


if __name__ == '__main__':
    main()
