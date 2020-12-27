list = []
R = []
for i in range(0, 10):
    list.append(int(input()))

for i in range(0, 10):
    R.append(list[i] % 42)

R = set(R)
print(len(R))