#! /usr/bin/env python3

from random import randint
from secret import flag

try:
  l = randint(60, 70)
  r = randint(0, 1 << l)
  print("Guess a number!")
  print("The number is in range 0 ~ 2^{}".format(l))
  for _ in range(l+1):
    g = input("Your guess: ")
    g = int(g)
    if g < r:
      print("Too small!")
    elif g > r:
      print("Too big!")
    else:
      print("You are correct!")
      print(flag)
      break
except:
  print("")
  print("What the???")
