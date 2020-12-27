T = int(input())
result = []

for i in range(0, T):
    A, B = map(int, input().split())
    result.append(A+B)

for i in range(0, T):
    print(result[i])