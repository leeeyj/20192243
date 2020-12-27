import sys
N, X = map(int, input().split())
A = sys.stdin.readline().split()
for i in range (0, N):
    if int(A[i]) < X:
        print(A[i], end=' ')