#! /usr/bin/env python3

import random
from public import pk1
from secret import sk1
from utils import prover_interactive

def protocol():
    p = pk1['p']
    g = pk1['g']
    y = pk1['y']
    x = sk1
    assert pow(g, x, p) == y, "Wrong key pair. Contact TA."
    prover_interactive(p, g, y, x)

if __name__ == "__main__":
    protocol()
