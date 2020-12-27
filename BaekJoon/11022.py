T = int(input())
A_input = []
B_input = []
result = []

for i in range(0, T):
    A, B = map(int, input().split())
    A_input.append(A)
    B_input.append(B)
    result.append(A+B)

for i in range(0, T):
    print("Case #", end='')
    print(i+1, end=': ')
    print(A_input[i], end=' + ')
    print(B_input[i], end=' = ')
    print(result[i])

