N = int(input())
new = N
count = 0
while True:
    new = (int(new / 10) + new % 10) % 10 + (new % 10) * 10
    if new != N:
        count += 1
    elif new == N:
        count += 1
        break

print(count)