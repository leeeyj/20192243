import sys

N = int(input())

A = sys.stdin.readline().split()
max = int(A[0])
min = int(A[0])

for i in range (0, N):
    if max < int(A[i]):
        max = int(A[i])
    elif min > int(A[i]):
        min = int(A[i])

print(min, max)
