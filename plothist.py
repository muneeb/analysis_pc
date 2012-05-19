#!/usr/bin/python
import sys
import pyusf

from matplotlib import pyplot as plt
from uart.utils import print_and_exit
from uart.hist  import Hist
from uart.hist  import Cdf

usage_str = "Usage: plothist.py [OUTFILE] [INFILES...]"

class Args:
    def __init__(self):
        self.o_file_name  = None
        self.i_file_names = None

    def parse(self):
        if len(sys.argv) < 3:
            print_and_exit(usage_str)
        self.o_file_name = sys.argv[1]
        self.i_file_names = sys.argv[2:]


def plot(hists, file_name):
    plt.hold(True)
    for h in hists:
        points = h.dict.items()
        points.sort(lambda (x1, y1), (x2, y2): cmp(x1, x2))
        x = map(lambda (x, y): x, points)
        y = map(lambda (x, y): y, points)
        plt.semilogx(x[1:-1], y[1:-1]) # do not plot dangling
    plt.hold(False)
    plt.savefig(file_name, format = "pdf")

def main():
    args = Args()
    args.parse()

    hists = []
    for file_name in args.i_file_names:
        h = Hist()
        h.load(file_name)
        hists.append(Cdf(h.dict))

    plot(hists, args.o_file_name)

if __name__ == "__main__":
    main()
