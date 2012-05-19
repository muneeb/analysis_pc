#!/usr/bin/python
import sys
import pyusf

from optparse   import OptionParser
from uart.utils import print_and_exit
from uart.hist  import Hist

class Args:
    def __init__(self):
        self.i_file_name1 = None
        self.i_file_name2 = None
        self.file_type = ""
        self.o_file_name = ""

        self.cpi1 = 1.0
        self.cpi2 = 1.0

        self.mix1 = 0.25
        self.mix2 = 0.25

    def parse(self):
        usage = "usage: %prog [OPTIONS...] FILE1 FILE2"
        parser = OptionParser(usage)

        parser.add_option("-o", "--out-file",
                          type = "str", default = None,
                          dest = "o_file_name",
                          help = "Output file name",
                          metavar = "FILE")

        parser.add_option("-t", "--type",
                          type = "str", default = "usf",
                          dest = "file_type",
                          help = "Input file type",
                          metavar = "STRING")

        parser.add_option("-c", "--cpi",
                          type = "str", default = "1.0,1.0",
                          dest = "cpi",
                          help = "List of cpis",
                          metavar = "cpi1,cpi2")

        parser.add_option("-i", "--inst-mix",
                          type = "str", default = "0.25,0.25",
                          dest = "mix",
                          help = "List of instruction mixes",
                          metavar = "mix1,mix2")

        (opts, args) = parser.parse_args()

        cpi = map(float, opts.cpi.split(","))
        if len(cpi) != 2:
            print_and_exit("args: cpi")
        self.cpi1 = cpi[0]
        self.cpi2 = cpi[1]

        mix = map(float, opts.mix.split(","))
        if len(mix) != 2:
            print_and_exit("args.mix")
        self.mix1 = mix[0]
        self.mix2 = mix[1]

        if len(args) == 2:
            self.i_file_name1 = args[0]
            self.i_file_name2 = args[1]
        else:
            print_and_exit("args: files")

        self.o_file_name = opts.o_file_name
        self.file_type = opts.file_type


def parse_usf(usf_file):
    dict_ = {}
    for event in usf_file:
        if event.type == pyusf.USF_EVENT_SAMPLE:
            rdist = event.end.time - event.begin.time - 1
        elif event.type == pyusf.USF_EVENT_DANGLING:
            rdist = sys.maxint
        else:
            continue

        if dict_.has_key(rdist):
            dict_[rdist] += 1
        else:
            dict_[rdist] = 1

    return Hist(dict_)

def my_round(x):
    return int(round(x))

def share_hist(hist1, cpi1, cpi2, inst_mix1, inst_mix2):
    dict_ = {}
    for rdist1, count1 in hist1:
        cycles = (rdist1 * cpi1) / inst_mix1
        rdist2 = (cycles / cpi2) * inst_mix2
        dict_[my_round(rdist1 + rdist2)] = count1
    return Hist(dict_)

def read_hist(file_name1, file_name2, file_type):
    if file_type == "usf":
        try:
            usf_file1 = pyusf.Usf(file_name1)
            usf_file2 = pyusf.Usf(file_name2)
        except IOError, e:
            print_and_exit(str(e))

        hist1 = parse_usf(usf_file1)
        hist2 = parse_usf(usf_file2)

        usf_file1.close()
        usf_file2.close()
    elif file_type == "hist":
        hist1 = Hist()
        hist2 = Hist()

        hist1.load(file_name1)
        hist2.load(file_name2)
    else:
        print_and_exit("XXX")

    return hist1, hist2

def main():
    args = Args()
    args.parse()

    hist1, hist2 = read_hist(args.i_file_name1, args.i_file_name2, args.file_type)

    share_hist1 = share_hist(hist1, args.cpi1, args.cpi2, args.mix1, args.mix2)
    share_hist2 = share_hist(hist2, args.cpi2, args.cpi1, args.mix2, args.mix1)

    share_hist_merged = share_hist1 + share_hist2

    share_hist_merged.dump(args.o_file_name)
    share_hist1.dump(args.o_file_name + ".0")
    share_hist2.dump(args.o_file_name + ".1")

if __name__ == "__main__":
    main()
