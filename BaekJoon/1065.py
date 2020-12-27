N = int(input())
split = []
count = 0
for i in range(1, N+1):
    while i != 0:
        A = i % 10
        split.append(A)
        i = int(i / 10)
    if len(split) > 1:
        d = split[1] - split[0] # 공차
        if split[0] + d * (len(split)-1) == split[len(split)-1]:
            count += 1
    else:
        count += 1
    split.clear()
print(count)

