#----------------------------------
# 암호분석 2021
#----------------------------------

import TC20_lib
import pickle # 변수저장
import random # 난수생성
import copy   # deep copy 


#============================================================
# 이전에 만든 함수들
#============================================================
#--- int(4bytes) to list 0x12345678 -> [ 0x12, 0x34, 0x56, 0x78 ]
def int2list(n):
    out_list = []
    out_list.append( (n >> 24) & 0xff )
    out_list.append( (n >> 16) & 0xff )
    out_list.append( (n >>  8) & 0xff )
    out_list.append( (n      ) & 0xff )

    return out_list

#--- list to int [ 0x12, 0x34, 0x56, 0x78 ] -> 0x12345678
def list2int(l):
    n = 0
    num_byte = len(l)
    for i in range(len(l)):
        n += l[i] << 8*(num_byte - i -1)
        
    return n

#- 변수를 파일에 저장하기
def save_var_to_file(var, filename):
    f = open(filename, 'w+b')
    pickle.dump(var, f)
    f.close()
    
#- 파일에서 변수를 가져오기
def load_var_from_file(filename):
    f = open(filename, 'rb')
    var = pickle.load(f)
    f.close()
    return var
#============================================================
    
#--------------------------------
# 평문-암호문(32비트): PT = [*,*,*,*] --> CT = [*,*,*,*]
# 키 크기
key_bit = 24 # 키공간 24비트 key = [0,*,*,*]

#---------------------------------
# TMTO Table: { SP:EP }
#   #SP = #EP = 2^8,   #chains = 2^8, #tables = 2^8

#============================================================
# P0 : 선택평문 (공격자가 획득 가능한 암호문에 대응되는 평문)
# X_{j+1} = E(P0, X_{j})  # key bit = block size
# X_{j+1} = R( E(P0, X_{j}) )  # R: 32비트 [*,*,*,*] -> 24비트 [0,*,*,*]
# SP = X0(Key) -> X1 -> X2 -> ... -> Xt = EP  (encryption key chain)
#============================================================

#------------
# R: 32비트 -> 24비트 
# R: [a,b,c,d] -> [0,b,c,d]
def R(ct):
    #next_key = ct
    next_key = copy.deepcopy(ct)
    next_key[0] = 0
    return next_key

#-------------
# Encryption key chain 만들기
#   SP = (24비트 랜덤키)
#   P0 = (선택평문, 고정값)    
#    t = 체인의 길이
def chain_EP(SP, P0, t):
    Xj = SP
    for j in range(0,t):
        ct = TC20_lib.TC20_Enc(P0, Xj)
        Xj = R(ct)   # next Xj 
    return Xj


#===========
# 확인용 함수 (공격에는 불필요)    
def chain_EP_debug_print(SP, P0, t):
    Xj = SP
    print('SP =', SP)
    for j in range(0,t):
        ct = TC20_lib.TC20_Enc(P0, Xj)
        Xj = R(ct)   # next Xj 
        print(' -> ', ct, ' -> ', Xj)
    return Xj

#===========
# 확인용 함수 (공격에는 불필요)       
def chain_EP_debug_file(SP, P0, t, chain_num, table_num):
    file_name = 'debug/TMTO-chain-' + str(table_num) +'-' + str(chain_num) + '.txt'
    f = open(file_name, 'w+')
    Xj = SP
    #print('SP =', SP)
    f.write('SP = [0, %d, %d, %d] \n' %(Xj[1], Xj[2], Xj[3]))
    for j in range(0,t):
        ct = TC20_lib.TC20_Enc(P0, Xj)
        Xj = R(ct)  # X_{j+1}
        #print('-->', ct, ' -->', Xj)
        f.write(' --> [%d, %d, %d, %d] ' %(ct[0], ct[1], ct[2], ct[3]))
        f.write(' --> [%d, %d, %d, %d] \n' %(Xj[0], Xj[1], Xj[2], Xj[3]))
    f.close()
    return Xj

#--------------------------------
# TMTO 테이블 한개 만들기
# 입력:
#      P0: 선택(고정)평문
#       m: #SP (행의 개수)    m=2^8: SP1 ~ SP2^8
#       t: 체인의 길이(열)    j=0, ... , j=t
#     ell: 테이블 번호        ell = 0 ~ 255
def make_one_tmto_table(P0, m, t, ell):
    tmto_dic = {}  # (SP,EP), 정렬기준 EP (EP를 검색하기 위해)
    for i in range(0,m): 
        SP = [0, random.randint(0,255), random.randint(0,255), random.randint(0,255) ]
        EP = chain_EP_debug_file(SP, P0, t, i, ell)
        # EP = chain_EP(SP, P0, t)
        SP_int = list2int(SP)
        EP_int = list2int(EP)
        tmto_dic[EP_int] = SP_int
    file_name = 'tmto_table/TMTO-' + str(ell) + '.dic'
    save_var_to_file(tmto_dic, file_name)
     
#---------------------
# TMTO 테이블 전체 만들기
# 입력:
#   P0: 고정평문 
#   m: 행(row)의 개수 (체인의 개수)
#   t: 열(col)의 개수 (체인의 길이)
#   num_of_tables: TMTO 테이블 개수 (=256)   
def make_all_tmto_tables(P0, m, t, num_of_tables):
    print('making TMTO tables', end='')
    for ell in range(0, num_of_tables):
        make_one_tmto_table(P0, m, t, ell)
        print('.', end='')
    print('\n All TMTO tables are created.')


#=========
# Test Run

random.seed(1234)  #고정된 seed --> 항상 같은 결과(랜덤)

SP = [0,1,2,3]    
P0 = [1,2,3,4]
m = 256
t = 256
num_of_tables = 256

#=====================
# (단계1) TMTO 테이블 만들기 (Pre-computation)
#=====================
# make_all_tmto_tables(P0, m, t, num_of_tables)


#=====================
# (단계2) 온라인 공격(획득 암호문에 대한 암호키 찾기)
#=====================
# 실제 사용한 암호키: Key = [0, 20, 90, 139]
# ct1 = E(P0, Key)

#--------------
# 한개의 테이블에 대한 키 탐색
def one_tmto_table_search(ct, P0, m, t, ell):
    key_candid_list = []
    file_name = 'tmto_table/TMTO-' + str(ell) + '.dic'
    tmto_dic = load_var_from_file(file_name)

    Xj = R(ct)
    current_j = t
    for idx in range(0,t):
        Xj_int = list2int(Xj)
        
        if Xj_int in tmto_dic: # Xj가 EP에 있는가?
            SP = int2list(tmto_dic[Xj_int]) # dic = { EP:SP }
            key_guess = chain_EP(SP, P0, current_j - 1)
            key_candid_list.append(key_guess)
        
        new_ct = TC20_lib.TC20_Enc(P0,Xj)
        Xj = R(new_ct)
        current_j = current_j - 1

    return key_candid_list


#================
ct1= [100, 107, 220, 57]
key_pool = []
print("TMTO Attack", end='')
for ell in range(0, num_of_tables):
    key_list = one_tmto_table_search(ct1, P0, m, t, ell)
    key_pool += key_list
    print('.', end='')
    
print('\n Attack complete!\n')
print('key_pool =', key_pool)

pt2 = [5,6,7,8]
ct2 = [72, 215, 32, 51]
final_key = []

for key in key_pool:
    ct_result = TC20_lib.TC20_Enc(pt2, key)
    if ct_result == ct2:
        final_key.append(key)

print('Final key =', final_key)   





