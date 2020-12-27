A = []
for i in range(0, 9):
    A.append(int(input()))

max = A[0]
count = 1
for i in range(0, 9):
    if max < A[i]:
        max = A[i]

print(max)
print(A.index(max)+1)
