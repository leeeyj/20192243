import sys
N = int(input())
input = sys.stdin.readline().split()
score = []
new_score = []

for i in range(0, N):
    score.append(int(input[i]))

score.sort()
max = score.pop()
new_score.append(100)
for i in range(0, len(score)):
    new_score.append((score.pop()/max) * 100)

mean = 0
for i in range(0, len(new_score)):
    mean += new_score[i]

print(mean/N)
