C = int(input())

rate_list = []
for i in range(0, C):
    rate = 0
    score = list(map(int, input().split()))
    mean = sum(score[1:]) / score[0]
    for j in score[1:]:
        if j > mean:
            rate += 1
    rate = (rate / score[0]) * 100
    rate_list.append(rate)

for i in rate_list:
    print("%0.3f" % i, end='')
    print("%")

