#!/usr/bin/python

import string
import sys
import re
import operator
import os
import pyusf
import read_datatrace
import math
import pprint
import disassm

from itertools import groupby

from uart.hist import Hist
import uart.sample_filter as sample_filter

from optparse import OptionParser


class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-l",
                          type="str", default=None,
                          dest="addr_file",
                          help="Specify the list containing addresses of delinqeunt loads")

        parser.add_option("-p", "--path",
                          type="str", default=os.curdir,
                          dest="path",
                          help="Specify path for burst sample files")

        parser.add_option("-e",
                          type="str", default=None,
                          dest="exec_file",
                          help="Specify the executable to inspect")
        
        parser.add_option("-n", "--num-samples",
                          type="int", default=None,
                          dest="num_samples",
                          help="Number of samples to be considered for analysis")

        parser.add_option("-f", "--filter",
                          type="str", default="all()",
                          dest="filter",
                          help="Filter for events to display in histogram.")

        (opts, args) = parser.parse_args()

        self.re_hex_address = re.compile("0[xX][0-9a-fA-F]+")

        self.path = opts.path
        self.line_size = 64
        self.filter = opts.filter
        self.addr_file = opts.addr_file
        self.num_samples = opts.num_samples
        self.exec_file = opts.exec_file


def open_sample_file(file_name, line_size=64):
    try:
        usf_file = pyusf.Usf()
        usf_file.open(file_name)
    except IOError, e:
        print >> sys.stderr, "Error: %s" % str(e)
#        print >> sys.stderr, file_name
        return None

    if usf_file.header.flags & pyusf.USF_FLAG_TRACE:
        print >> sys.stderr, "Error: Specified file is a trace."
        return None

    if not usf_file.header.line_sizes & line_size:
        print >> sys.stderr, \
            "Eror: Specified line size does not exist in sample file."
        return None

    return usf_file

def read_delinq_loads(addr_file):
    
    delinq_loads = []

    try:
        dfile = open( addr_file, "r" )
        for line in dfile:
            cols = line.split(" ")
            delinq_loads.append( cols[0] )
        dfile.close()
    except IOError, e:
        print >> sys.stderr, "Error: %s" % str(e)
        return None

    return delinq_loads

def analyze_inter_pc_strides(global_smp_datatrace_hist):

    global_stride_pc_corr_hist = {}
    
    for smp_time in global_smp_datatrace_hist.keys():
        
        global_stride_pc_corr_hist[smp_time] = []
        
        for page_addr in global_smp_datatrace_hist[smp_time].keys():
            addr_pc_list = global_smp_datatrace_hist[smp_time][page_addr]

            for tup_curr, tup_prev in zip(addr_pc_list[:-1], addr_pc_list[1:]):
                (addr_curr, pc_curr) = tup_curr
                (addr_prev, pc_prev) = tup_prev

                stride = addr_curr - addr_prev

                pc_corr_tup = (pc_prev, pc_curr)
                
                pc_corr_stride_tup = (stride, pc_corr_tup)

                global_stride_pc_corr_hist[smp_time].append(pc_corr_stride_tup)

    global_stride_pc_corr_hist_filtered = {}

    for time in global_stride_pc_corr_hist.keys():
        pc_corr_stride_tup_list = global_stride_pc_corr_hist[time]

        #reverse the list so that we can iterate earlier to later
        pc_corr_stride_tup_list =  pc_corr_stride_tup_list[::-1]

        global_stride_pc_corr_hist_filtered[time] = []
        pc_corr_stride_tup_list_filtered = []

        #prev prev
        pp_stride = 0
        for tup_prev, tup_curr  in zip(pc_corr_stride_tup_list[:-1], pc_corr_stride_tup_list[1:]):
            (stride_curr, pc_corr_tup_curr) = tup_curr
            (stride_prev, pc_corr_tup_prev) = tup_prev

            if stride_curr == stride_prev and stride_curr != 0:
                pc_corr_stride_tup_list_filtered.append(tup_prev)
            elif stride_prev == pp_stride and stride_prev != 0:
                pc_corr_stride_tup_list_filtered.append(tup_prev)
                sent_tup = (0, (0,0))
                pc_corr_stride_tup_list_filtered.append(sent_tup)
                pp_stride = 0
                continue

            pp_stride = stride_prev
            
        if stride_curr == stride_prev:
            pc_corr_stride_tup_list_filtered.append(tup_curr)

        global_stride_pc_corr_hist_filtered[time] = pc_corr_stride_tup_list_filtered

#    pp = pprint.PrettyPrinter(depth=4)
#    pp.pprint(global_stride_pc_corr_hist_filtered)

    return global_stride_pc_corr_hist_filtered


def filter_delinq_loads_stride_traces(global_stride_pc_corr_hist_filtered, delinq_loads):

    filter_delinq_pc = lambda x,y: (str(x[1][0]) == str(y)) or (str(x[1][1]) == str(y))
    filter_start_pc = lambda x: x[1][0]
    
    pp = pprint.PrettyPrinter(depth=4)

    mem_instr_addr_l = []
    
    for time in global_stride_pc_corr_hist_filtered.keys():
        
        print "time: %ul"%(time)

        tlist = global_stride_pc_corr_hist_filtered[time]
        flist=[list(group) for k, group in groupby(tlist, lambda x: x == (0,(0,0))) if not k]
     
        for dlist in flist:
            res = False
            for pc in delinq_loads:
                for tup in dlist:
                
                    res = filter_delinq_pc(tup, pc)
                    if res:
                        
                        addr_l = map(filter_start_pc, dlist)
                        mem_instr_addr_l += addr_l
                        sent_tup = (0, (0,0))
                        dlist.append(sent_tup)
                        pp.pprint(dlist)
                        break
            if res:
                break

    return mem_instr_addr_l

def account_stack_ops(exec_file, mem_instr_addr_l):
    
    cfg = disassm.get_func_disassm(exec_file, mem_instr_addr_l[0])
    
    stack_op_count = 0
    
    for pc in mem_instr_addr_l:
        if pc in cfg.ins_tags_dict.keys():
                if "Stack" in cfg.ins_tags_dict[pc]:
                    stack_op_count += 1
        elif pc != 0:   
            cfg = disassm.get_func_disassm(exec_file, pc)


    print stack_op_count, len(mem_instr_addr_l)
    stack_op_ratio = float(stack_op_count)/float(len(mem_instr_addr_l))

    print "Stack operation ratio: %lf"%(stack_op_ratio)

def main():

    global_smp_datatrace_hist = {}
    global_pc_stride_hist = {}

    conf = Conf()

    listing = os.listdir(conf.path)

    if conf.addr_file != None:
        delinq_loads = read_delinq_loads(conf.addr_file)

    if not conf.num_samples is None:

        num_sample_files = len(listing)

        files_required = math.ceil(float(conf.num_samples) / float(1200)) + 1 # 1200 is the number of samples per file

        files_sapcing = int(math.ceil(float(num_sample_files) / float(files_required)))

        print >> sys.stderr, "files spacing: %d"%(files_sapcing)

        if files_sapcing == 0:
            files_sapcing = 1

        file_no = 0

        listing = []
        
        while file_no < num_sample_files:
            file_name = "sample."+str(file_no)
            listing.append(file_name)
            file_no += files_sapcing

    for infile in listing:

        infile = conf.path + infile

        usf_file = open_sample_file(infile, conf.line_size)
        
        if usf_file == None:

            continue
        
        try:
            burst_hists = read_datatrace.usf_read_events(usf_file,
                                                line_size=conf.line_size,
                                                filter=conf.filter)

        except IOError, e:
            continue

        usf_file.close()

        for (pc_freq_hist, pc_time_hist, smp_datatrace_hist) in burst_hists:
            continue

        global_smp_datatrace_hist.update(smp_datatrace_hist)

    global_stride_pc_corr_hist_filtered = analyze_inter_pc_strides(global_smp_datatrace_hist)

    if conf.addr_file != None:
        mem_instr_addr_l = filter_delinq_loads_stride_traces(global_stride_pc_corr_hist_filtered, delinq_loads)
        
        if conf.exec_file != None:
            account_stack_ops(conf.exec_file, mem_instr_addr_l)

if __name__ == "__main__":
    main()
