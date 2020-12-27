# Self Number 구하는 문제 조금 어려웠음
def self_number(arr, num):
    hap = num
    if arr.count(num) == 0:
        arr.append(num)
        while num != 0:
            hap += num % 10
            num = int(num / 10)
        if hap < 10001:
            arr.append(hap)
        return arr
    elif arr.count(num) != 0:
        for i in range(0, arr.count(num)):
            arr.remove(num)
        while num != 0:
            hap += num % 10
            num = int(num / 10)
        if hap < 10001:
            arr.append(hap)
        return arr

A = []
for i in range(1, 10001):
    A = self_number(A, i)
for i in range (0, len(A)):
    print(A[i])