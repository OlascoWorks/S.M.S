##########
import math

def main():
    a = int(input("provide an 'a' value\t"))
    b = int(input("provide an 'b' value\t"))
    c = int(input("provide an 'c' value\t"))

    if type(a) != int or type(b) != int or type(c) != int:
        return "Invalid inputs"

    ans = (-b + math.sqrt((b*b) -(4*b*c)))/2*a

    return ans


print(main())