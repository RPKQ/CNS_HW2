#! /usr/bin/env python3

import random
import time
from public import pk1, pk2, pk3, pk4
from secret import flag1, flag2, flag3, flag4
from utils import verifier_interactive, verifier_non_interactive

def getflag1():
    p = pk1['p']
    g = pk1['g']
    y = pk1['y']
    print('Alice\'s public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
    if verifier_interactive(p, g, y):
        print(f'I think you\'re Alice. Here is the flag: {flag1}')
    else:
        print('Hello stranger~')

    
def getflag2():
    p = pk2['p']
    g = pk2['g']
    y = pk2['y']
    print('Alice\'s public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
    random.seed(int(time.time()))
    if verifier_interactive(p, g, y):
        print(f'I think you\'re Alice. Here is the flag: {flag2}')
    else:
        print('Hello stranger~')

    
def getflag3():
    p = pk3['p']
    g = pk3['g']
    y = pk3['y']
    print('Alice\'s public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
    if verifier_non_interactive(p, g, y):
        print(f'I think you\'re Alice. Here is the flag: {flag3}')
    else:
        print('Hello stranger~')


def getflag4():
    p = pk4['p']
    g = pk4['g']
    y = pk4['y']
    print('Alice\'s public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
    if verifier_interactive(p, g, y):
        print(f'I think you\'re Alice. Here is the flag: {flag4}')
    else:
        print('Hello stranger~')


def menu():
    print('===================')
    print(' 1. flag1          ')
    print(' 2. flag2          ')
    print(' 3. flag3          ')
    print(' 4. flag4          ')
    print(' 5. exit           ')
    print('===================')

if __name__ == "__main__":
    while True:
        menu()
        choice = input('Your choice: ').strip()
        try:
            choice = int(choice)
        except:
            print('Invalid Choice')
            continue
        if choice == 1:
            getflag1()
        elif choice == 2:
            getflag2()
        elif choice == 3:
            getflag3()
        elif choice == 4:
            getflag4()
        elif choice == 5:
            break
        else:
            print('Invalid Choice')
