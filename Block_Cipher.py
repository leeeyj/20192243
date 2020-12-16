# ================================================================
#
# author: 국민대학교 정보보안암호수학과 20192243 이용진
# Kookmin Univ. Information security math & cryptography
#
# Project : Develop My own block cipher-based encryption library.
# ================================================================

# ======================================================================================================================
# 코드 설명
# 1.
# Enc_Operation_Check 함수는 암호화가 잘 진행되었는지 확인하는 함수입니다.
#
# 2.
# Enc_Operation_Check 함수에서는 ECB CBC mode 의 경우
# 평문, 평문 + 패딩, 암호문을 확인할 수 있고
# CFB OFB CTR mode 의 경우
# 패딩이 필요하지 않기 때문에 평문, 암호문을 확인할 수 있습니다.
#
# 3.
# Dec_Operation_Check 함수는 복호화가 잘 진행되었는지 확인하는 함수입니다.
# Enc_Operation_Check 와 비슷하게 암호, 복호화 값 + 패딩(ECB, CBC), 복호화 값을
# mode 에 따라서 필요한 것을 확인할 수 있습니다.
#
# 4.
# 사용자는 원하는 mode 를 선택하고 enc_file 와 dec_file 함수를 통해 암/복호화를 진행할 수 있습니다.
# 평문은 enc_file 로 암호는 dec_file 을 사용합니다.
# ECB CBC mode 복호화 경우 dec_file 함수에서 decrypt 를 사용합니다.
# CFB OFB CTR mode 복호화 경우 dec_file 함수에서 encrypt 를 사용합니다.
#
# 5.
# 패딩은 # PKCS7 Padding 방식을 사용하였습니다.
# Example:
#   plain: bc20ed959ceb8ba42e20e2809d0d0a
#   plain + padding = bc20ed959ceb8ba42e20e2809d0d0a01 + 10101010101010101010101010101010
# 평문이 16배수인 경우 패딩을 10101010101010101010101010101010 한 블럭을 추가 해줍니다.
# 복호화를 진행할 때 마지막 한 바이트만 확인해주고 바이트 값 만큼 패딩을 제거 해줍니다.
# Example:
#   plain: bc20ed959ceb8ba42e20e2809d0d
#   plain + padding = bc20ed959ceb8ba42e20e2809d0d01
#   decrypt: bc20ed959ceb8ba42e20e2809d0d01 마지막 바이트 확인(01) => 1바이트 제거
#
# 6.
# 코드 내부에서 사용하는 buffer1 은 Enc_Operation_Check 와 Dec_Operation_Check 함수를 돌려보기 위한 테스트용 변수입니다.
#
# 7.
# enc/dec_file 함수 내부에 각각의 모드에 맞는 Test_Vector 가 포함되어있습니다.
#
# ★8.
# Block_Cipher 는 1 block 을 암호화 할 때 Aes128을 사용합니다. (key 를 128-bit 입력하기 때문)
# 파이썬 pycryptodome library 에는 Aes128 을 단독으로 사용할 수 없는 것 같습니다...
# ECB 모드는 평문 한 블록을 암호화하면 암호문 한 블록을 주기 때문에
# cipher = AES.new(key, mode = AES.MODE_ECB) 가 Aes128을 단독으로 사용하는 것과 다름없다라고 생각했습니다.
# 그래서 저는 블록 암호화 함수를 cipher = AES.new(key, mode = AES.MODE_ECB) 로 두고 사용하였습니다.
# cipher 사용시 16바이트 입력만 암호화를 해줍니다.
# 위의 암호화 방식을 이용하여 Block_Cipher_Mode 를 구현하였습니다.
#
# 9. Test Vectors + padding
# key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
# iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
# iv = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff') : This iv only use testing CTR mode
#
# plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a
#                        ae2d8a571e03ac9c9eb76fac45af8e51
#                        30c81c46a35ce411e5fbc1191a0a52ef
#                        f69f2445df4f9b17ad2b417be66c3710')
#
# cipher_ECB = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97
#                             f5d3d58503b9699de785895a96fdbaaf
#                             43b1cd7f598ece23881b00e3ed030688
#                             7b0c785e27e8ad3f8223207104725dd4
#                             a254be88e037ddd9d79fb6411c3f9df8')
#
# cipher_CBC = bytes.fromhex('7649abac8119b246cee98e9b12e9197d
#                             5086cb9b507219ee95db113a917678b2
#                             73bed6b8e3c1743b7116e69e22229516
#                             3ff1caa1681fac09120eca307586e1a7
#                             8cb82807230e1321d3fae00d18cc2012')
#
# ECB 와 CBC는 plain이 16의 배수이기 때문에 10101010101010101010101010101010 한 블럭 패딩이 되었다.
# 그래서 ECB 와 CBC 의 암호문은 16바이트 더 늘어났다.
#
# cipher_CFB = bytes.fromhex('3b3fd92eb72dad20333449f8e83cfb4a
#                             c8a64537a0b3a93fcde3cdad9f1ce58b
#                             26751f67a3cbb140b1808cf187a4f4df
#                             c04b05357c5d1c0eeac4c66f9ff7f2e6')
#
# cipher_OFB = bytes.fromhex('3b3fd92eb72dad20333449f8e83cfb4a
#                             7789508d16918f03f53c52dac54ed825
#                             9740051e9c5fecf64344f7a82260edcc
#                             304c6528f659c77866a510d9c1d6ae5e')
#
# cipher_CTR = bytes.fromhex('874d6191b620e3261bef6864990db6ce
#                             9806f66b7970fdff8617187bb9fffdff
#                             5ae4df3edbd5d35e5b4f09020db03eab
#                             1e031dda2fbe03d1792170a0f3009cee')
#
# ======================================================================================================================

import binascii
from Crypto.Cipher import AES

# Checking Operation
def Enc_Operation_Check(plain, plain_pad, cipher, Mode):
    # Use ECB and CBC
    if Mode == 'ECB' or Mode == 'CBC':
        print('Enc_Operation_Check,  mode = ' + Mode)

        # 평문 바이트 값 출력
        print("plain file = ", end='')
        print(binascii.hexlify(plain))

        # 평문 바이트 + 패딩 값 출력
        print("plain file + padding = ", end='')
        print(binascii.hexlify(plain_pad))

        # 평문 암호화 바이트 값 출력 (패딩 추가함)
        print("enc block = ", end='')
        print(binascii.hexlify(cipher))

    # Use CFB OFB CTR
    # CFB OFB CTR mode don't need padding
    # CFB OFB CTR mode plain and cipher length are same : |P| = |C|
    # In this function, You can check that plain and cipher length are same
    if Mode == 'CFB' or Mode == 'OFB' or Mode == 'CTR':
        print('Enc_Operation_Check,  mode = ' + Mode)

        # 평문 바이트 값 출력
        print("plain file = ", end='')
        # print(len(plain))  # |C| = |P| 비교하기 위함
        print(binascii.hexlify(plain))

        # 평문 암호화 바이트 값 출력
        print("enc block = ", end='')
        # print(len(cipher)) # |C| = |P| 비교하기 위함
        print(binascii.hexlify(cipher))

def Dec_Operation_Check(cipher, cipher_dec_pad, cipher_dec_remove_pad, Mode):
    # Use ECB and CBC
    if Mode == 'ECB' or Mode == "CBC":
        print('\n')
        print('Dec_Operation_Check,  mode = ' + Mode)

        # 암호 바이트 값 출력
        print("enc_block = ", end='')
        print(binascii.hexlify(cipher))

        # 암호 복호화 바이트 출력_before removing padding (plain file + padding 값과 비교)
        print("dec_block_before_remove_padding = ", end='')
        print(binascii.hexlify(cipher_dec_pad))

        # 복호화 바이트 출력_after removing padding (plain과 비교)
        print("dec_block = ", end='')
        print(binascii.hexlify(cipher_dec_remove_pad))

    # Use CFB OFB CTR
    # CFB OFB CTR mode don't need padding
    # CFB OFB CTR mode plain and cipher length are same : |P| = |C|
    # In this function, You can check that plain and cipher length are same
    if Mode == 'CFB' or Mode == 'OFB' or Mode == 'CTR':
        print('\n')
        print('Dec_Operation_Check,  mode = ' + Mode)

        # 암호 출력 + 암호문 길이 출력
        print("cipher file = ", end='')
        # print(len(plain))  # |C| = |P| 비교하기 위함
        print(binascii.hexlify(cipher))

        # 복호화 블록 출력 + 평문 길이 출력
        print("dec block = ", end='')
        # print(len(cipher)) # |C| = |P| 비교하기 위함
        print(binascii.hexlify(cipher_dec_remove_pad))

# Encrypt_file
def enc_file(read_file_name, write_file_name, key, IV, Mode):
    with open(read_file_name, "rb") as infile:
        with open(write_file_name, 'wb') as outfile:
            cipher = AES.new(key, mode = AES.MODE_ECB)
            # cipher is encryption function of block cipher

            # Test_Vector = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
            # Test_Vector 에 대한 암호화 값은 맨위 설명 주석에 있다.

            # Block Cipher mode ECB Encrypt function
            if Mode == 'ECB':
                enc_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector

                buffer1 = buffer
                # buffer1 은 operation check 를 위한 변수이다.

                if len(buffer) % 16 != 0:
                    # PKCS7 Padding
                    pad_val = 16 - len(buffer) % 16
                    pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
                    buffer += pad
                elif len(buffer) % 16 == 0:
                    # PKCS7 Padding ( 16 배수일 경우 10101010101010101010101010101010 block 추가)
                    pad_val = 16
                    buffer += pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
                    # 정상적인 복호화를 위해 패딩 값으로 이루어진 한 블럭을 더 추가로 암호화해준다.

                number_of_block = int(len(buffer) / 16)
                for i in range(1, number_of_block+1):
                    enc_block += cipher.encrypt(buffer[16*(i-1):16*i])

                Enc_Operation_Check(buffer1, buffer, enc_block, Mode)
                # Enc_operation_check is for testing

                outfile.write(enc_block)

            # Block Cipher mode CBC Encrypt function
            elif Mode == 'CBC':
                enc_block = bytes()
                compute_xor_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector

                buffer1 = buffer

                C = IV

                if len(buffer) % 16 != 0:
                    # PKCS7 Padding
                    pad_val = 16 - len(buffer) % 16
                    pad = pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val
                    buffer += pad
                elif len(buffer) % 16 == 0:
                    pad_val = 16
                    buffer += pad_val.to_bytes(1, byteorder='big', signed=True) * pad_val

                number_of_block = int(len(buffer) / 16)
                for i in range(1, number_of_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([buffer[16 * (i - 1):16 * i][j] ^ C[j]])
                    enc_block += cipher.encrypt(compute_xor_block)
                    C = cipher.encrypt(compute_xor_block)
                    # C = enc_block[16 * (i - 1):16 * i]
                    compute_xor_block = bytes()

                Enc_Operation_Check(buffer1, buffer, enc_block, Mode)

                outfile.write(enc_block)

            # Block Cipher mode CFB Encrypt function
            elif Mode == 'CFB':
                enc_block = bytes()
                compute_xor_block = bytes()
                last_block = bytes()

                buffer = infile.read()
                # buffer = Test_Vector

                buffer1 = buffer

                C = IV

                last_block_size = int(len(buffer) % 16)
                number_of_block = int((len(buffer) - last_block_size) / 16)

                for i in range(1, number_of_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([buffer[16 * (i - 1):16 * i][j] ^ cipher.encrypt(C)[j]])
                    enc_block += compute_xor_block
                    C = enc_block[16 * (i - 1):16 * i]
                    compute_xor_block = bytes()

                if last_block_size != 0:
                    for i in range(0, last_block_size):
                        last_block += bytes([cipher.encrypt(C)[:last_block_size][i] ^ buffer[16*number_of_block:][i]])
                    enc_block += last_block

                Enc_Operation_Check(buffer1, None, enc_block, Mode)

                outfile.write(enc_block)

            # Block Cipher mode OFB Encrypt function
            elif Mode == 'OFB':
                enc_block = bytes()
                compute_xor_block = bytes()
                last_block = bytes()

                buffer = infile.read()
                # buffer = Test_Vector

                buffer1 = buffer

                C = IV

                last_block_size = int(len(buffer) % 16)
                number_of_block = int((len(buffer) - last_block_size) / 16)

                for i in range(1, number_of_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([cipher.encrypt(C)[j] ^ buffer[16 * (i - 1):16 * i][j]])
                    enc_block += compute_xor_block
                    C = cipher.encrypt(C)
                    compute_xor_block = bytes()

                if last_block_size != 0:
                    for i in range(0, last_block_size):
                        last_block += bytes([cipher.encrypt(C)[:last_block_size][i] ^ buffer[16 * number_of_block:][i]])
                    enc_block += last_block

                Enc_Operation_Check(buffer1, None, enc_block, Mode)

                outfile.write(enc_block)

            elif Mode == 'CTR':
                enc_block = bytes()
                compute_xor_block = bytes()
                last_block = bytes()

                buffer = infile.read()
                # buffer = Test_Vector

                buffer1 = buffer

                ctr = IV
                ctr_int = int.from_bytes(IV, byteorder='big', signed=False)
                # ctr_int 는 바이트로 이루어진 IV를 정수로 바꾼 값을 저장한 변수이다.

                last_block_size = int(len(buffer) % 16)
                number_of_block = int((len(buffer) - last_block_size) / 16)

                for i in range(1, number_of_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([cipher.encrypt(ctr)[j] ^ buffer[16 * (i - 1):16 * i][j]])
                    enc_block += compute_xor_block
                    ctr = int.to_bytes((ctr_int + i) % (2 ** 128), 16, byteorder='big', signed=False)
                    compute_xor_block = bytes()

                if last_block_size != 0:
                    for i in range(0, last_block_size):
                        last_block += bytes([cipher.encrypt(ctr)[:last_block_size][i] ^ buffer[16 * number_of_block:][i]])
                    enc_block += last_block

                Enc_Operation_Check(buffer1, None, enc_block, Mode)

                outfile.write(enc_block)


# Decrypt_file
def dec_file(enc_file_name, dec_file_name, key, IV, Mode):
    with open(enc_file_name, "rb") as infile:
        with open(dec_file_name, 'wb') as outfile:
            decryptor = AES.new(key, AES.MODE_ECB)
            # decryptor is decrypt function of block cipher for ECB CBC mode

            cipher = AES.new(key, AES.MODE_ECB)
            # cipher is encrypt function of block cipher
            # CFB, OFB, CTR mode only need encrypt function to decrypt cipher

            # Test_Vector_ECB = bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4a254be88e037ddd9d79fb6411c3f9df8')
            # Test_Vector_CBC = bytes.fromhex('7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012')
            # Test_Vector_CFB = bytes.fromhex('3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6')
            # Test_Vector_OFB = bytes.fromhex('3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e')
            # Test_Vector_CTR = bytes.fromhex('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee')

            # Block Cipher mode ECB Decrypt function
            if Mode == 'ECB':
                dec_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector_ECB

                buffer1 = buffer

                number_of_enc_block = int(len(buffer) / 16)
                for i in range(1, number_of_enc_block+1):
                    dec_block += decryptor.decrypt(buffer[16*(i-1):16*i])

                pad_len = int(dec_block[len(dec_block) - 1]) # 마지막 바이트 확인

                Dec_Operation_Check(buffer1, dec_block, dec_block[:len(dec_block) - pad_len], Mode)
                dec_block = dec_block[:len(dec_block)-pad_len]
                outfile.write(dec_block)



            # Block Cipher mode CBC Decrypt function
            elif Mode == 'CBC':
                dec_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector_CBC

                buffer1 = buffer
                # buffer1은 오로지 테스트하기 위하여 사용

                compute_xor_block = bytes()
                number_of_enc_block = int(len(buffer) / 16)
                C = IV

                for i in range(1, number_of_enc_block+1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([decryptor.decrypt(buffer[16 * (i - 1):16 * i])[j] ^ C[j]])
                    dec_block += compute_xor_block
                    C = buffer[16 * (i - 1):16 * i]
                    compute_xor_block = bytes()

                pad_len = int(dec_block[len(dec_block) - 1])
                Dec_Operation_Check(buffer1, dec_block, dec_block[:len(dec_block) - pad_len], Mode)
                dec_block = dec_block[:len(dec_block) - pad_len]
                outfile.write(dec_block)

            # Block Cipher mode CFB Decrypt function
            elif Mode == 'CFB':
                dec_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector_CFB

                buffer1 = buffer

                compute_xor_block = bytes()
                last_block = bytes()
                C = IV

                last_block_size = int(len(buffer) % 16)
                number_of_enc_block = int((len(buffer) - last_block_size) / 16)

                for i in range(1, number_of_enc_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([buffer[16 * (i - 1):16 * i][j] ^ cipher.encrypt(C)[j]])
                    dec_block += compute_xor_block
                    C = buffer[16 * (i - 1):16 * i]
                    compute_xor_block = bytes()

                if last_block_size != 0:
                    for i in range(0, last_block_size):
                        last_block += bytes([cipher.encrypt(C)[:last_block_size][i] ^ buffer[16*number_of_enc_block:][i]])
                    dec_block += last_block

                Dec_Operation_Check(buffer1, dec_block, dec_block, Mode)
                outfile.write(dec_block)

            # Block Cipher mode OFB Decrypt function
            elif Mode == 'OFB':
                dec_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector_OFB

                buffer1 = buffer

                compute_xor_block = bytes()
                last_block = bytes()
                C = IV

                last_block_size = int(len(buffer) % 16)
                number_of_enc_block = int((len(buffer) - last_block_size) / 16)

                for i in range(1, number_of_enc_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([buffer[16 * (i - 1):16 * i][j] ^ cipher.encrypt(C)[j]])
                    dec_block += compute_xor_block
                    C = cipher.encrypt(C)
                    compute_xor_block = bytes()

                if last_block_size != 0:
                    for i in range(0, last_block_size):
                        last_block += bytes(
                            [cipher.encrypt(C)[:last_block_size][i] ^ buffer[16 * number_of_enc_block:][i]])
                    dec_block += last_block

                Dec_Operation_Check(buffer1, dec_block, dec_block, Mode)
                outfile.write(dec_block)

            # Block Cipher mode CTR Decrypt function
            elif Mode == 'CTR':
                dec_block = bytes()
                buffer = infile.read()
                # buffer = Test_Vector_CTR

                buffer1 = buffer
                compute_xor_block = bytes()
                last_block = bytes()

                ctr = IV
                ctr_int = int.from_bytes(IV, byteorder='big', signed=False)

                last_block_size = int(len(buffer) % 16)
                number_of_enc_block = int((len(buffer) - last_block_size) / 16)

                for i in range(1, number_of_enc_block + 1):
                    for j in range(0, 16):
                        compute_xor_block += bytes([cipher.encrypt(ctr)[j] ^ buffer[16 * (i - 1):16 * i][j]])
                    dec_block += compute_xor_block
                    ctr = int.to_bytes((ctr_int + i) % (2 ** 128), 16, byteorder='big', signed=False)
                    compute_xor_block = bytes()

                if last_block_size != 0:
                    for i in range(0, last_block_size):
                        last_block += bytes([cipher.encrypt(ctr)[:last_block_size][i] ^ buffer[16 * number_of_enc_block:][i]])
                    dec_block += last_block

                Dec_Operation_Check(buffer1, dec_block, dec_block, Mode)
                outfile.write(dec_block)


# Main
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
# ECB, CBC, CFB, OFB mode 전용 Test IV

# iv = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
# CTR mode 전용 Test IV

mode = "CTR"
# mode setting : ECB, CBC, CFB, OFB, CTR

r_file_name = "C:/Users/LeeYongJin/Desktop/Block_Cipher/Kerckhoffs Principle.txt." # Plain_file_name
w_file_name = "C:/Users/LeeYongJin/Desktop/Block_Cipher/Kerckhoffs Principle enc CBC.txt" # Enc_Plain_file_name
re_w_file_name = "C:/Users/LeeYongJin/Desktop/Block_Cipher/Kerckhoffs Principle dec CBC.txt" # Dec_Enc_Plain_file_name
# 원하는 파일 형태의 확장자로 file 지정하기

enc_file(r_file_name, w_file_name, key, iv, mode)
dec_file(w_file_name, re_w_file_name, key, iv, mode)


