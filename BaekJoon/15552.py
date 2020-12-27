import sys
T = int(input())
reslut = []
for i in range (0, T):
    A, B = map(int, sys.stdin.readline().split())
    reslut.append(A+B)
for i in range (0, T):
    print(reslut[i])
