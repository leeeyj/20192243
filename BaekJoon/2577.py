A = int(input())
B = int(input())
C = int(input())

result = list(str(A * B * C))
len = len(str(A * B * C))
for i in range(0, len):
    result[i] = int(result[i])

count = []
for i in range(0, 10):
    count.append(result.count(i))

for i in range(0, 10):
    print(count[i])
