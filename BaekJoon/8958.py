N = int(input())

score_list = []
for i in range(0, N):
    score_o = 0
    score = 0
    Quiz = list(input())
    for j in range(0, len(Quiz)):
        Quiz_pop = Quiz.pop()
        if Quiz_pop == 'O':
                score_o += 1
                score += score_o
        elif Quiz_pop == 'X':
                score_o = 0
    score_list.append(score)
    Quiz.clear()

for i in range(0, N):
    print(score_list[i])
