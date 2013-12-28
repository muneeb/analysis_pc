#!/usr/bin/python
import sys
import math
import os
import string
import gc

import operator

from optparse import OptionParser

from uart.hist import Hist
import uart.sample_filter as sample_filter

import pyusf
import lrumodel
import bypassutils
import missratio

import redirect_analysis
import trace_analysis
import ins_trace_analysis

__version__ = "$Revision$"

class PrefParams:

    def __init__(self, delinq_load_addr, pf_type, pd, l1_mr, l2_mr, l3_mr):
        self.delinq_load_addr = delinq_load_addr
        self.pf_type = pf_type
        self.pd = pd
        self.l1_mr = l1_mr
        self.l2_mr = l2_mr
        self.l3_mr = l3_mr


class Conf:
    def __init__(self):
        parser = OptionParser("usage: %prog [OPTIONS...] INFILE")

        parser.add_option("-l", "--line-size",
                          type="int", default="64",
                          dest="line_size",
                          help="Use a specific line size.")

        parser.add_option("-t", "--type",
                          type="str", default="pfonly",
                          dest="analysis_type",
                          help="Analysis Type: 'pfonly', 'cons', 'aggr' ")

        parser.add_option("-m", "--mem",
                          type="float", default="3.2",
                          dest="cyc_per_mop",
                          help="Cycles per memory operation for this benchmark. ")

        parser.add_option("-n", "--num-samples",
                          type="int", default=None,
                          dest="num_samples",
                          help="Number of samples to be considered for analysis")

        parser.add_option("--mem-lat",
                          type="float", default="170",
                          dest="memory_latency",
                          help="Average Memory latency ")
        
        parser.add_option("--l1-lat",
                          type="float", default="2",
                          dest="l1_latency",
                          help="Average L1 cache latency ")

        parser.add_option("--l2-lat",
                          type="float", default="20",
                          dest="l2_latency",
                          help="Average L2 cache latency ")

        parser.add_option("--l3-lat",
                          type="float", default="45",
                          dest="l3_latency",
                          help="Average L3 cache latency ")

        parser.add_option("--l1-size",
                          type="int", default="64",
                          dest="l1_size",
                          help="L1 size in kilobytes (KB) ")        

        parser.add_option("--l2-size",
                          type="int", default="512",
                          dest="l2_size",
                          help="L2 size in kilobytes (KB) ")        

        parser.add_option("--l3-size",
                          type="int", default="6144",
                          dest="l3_size",
                          help="L3 size in kilobytes (KB) ")  
        
        parser.add_option("--detailed-modeling",
                          type="int", default="0",
                          dest="detailed_modeling",
                          help="Use detailed modeling")

        parser.add_option("--report-delinq-loads-only",
                          type="int", default="0",
                          dest="report_delinq_loads_only",
                          help="Use detailed modeling")

        parser.add_option("--all-delinq-loads",
                          type="int", default="0",
                          dest="all_delinq_loads",
                          help="print all delinquent loads ")

        parser.add_option("-p", "--path",
                          type="str", default=os.curdir,
                          dest="path",
                          help="Specify path for burst sample files")

        parser.add_option("-e",
                          type="str", default=None,
                          dest="exec_file",
                          help="Specify the executable to inspect")
        
        parser.add_option("-f", "--filter",
                          type="str", default="all()",
                          dest="filter",
                          help="Filter for events to display in histogram.")

        parser.add_option("--stride-only-analysis",
                          type="int", default="0",
                          dest="stride_only",
                          help="only use stride information to generate prefetches")

        parser.add_option("--help-filters",
                          action="callback", callback=self.help_filters,
                          help="Display help about the filter language.")


        (opts, args) = parser.parse_args()

        if opts.line_size <= 0 or \
                opts.line_size & (opts.line_size - 1) != 0:
            print >> sys.stderr, "Invalid line size specified."
            sys.exit(1)

#        if len(args) == 0:
#            print >> sys.stderr, "No input file specified."
#            sys.exit(1)

        self.filter = sample_filter.from_str(opts.filter)
#        self.ifile_name = args[0]
        self.line_size = opts.line_size
        self.path = opts.path
        self.analysis_type = opts.analysis_type
        self.cyc_per_mop = opts.cyc_per_mop
        self.l3_latency = opts.l3_latency
        self.l2_latency = opts.l2_latency
        self.l1_latency = opts.l1_latency
        self.memory_latency = opts.memory_latency
        self.l3_size = opts.l3_size
        self.l2_size = opts.l2_size
        self.l1_size = opts.l1_size
        self.all_delinq_loads = opts.all_delinq_loads
        self.stride_only = opts.stride_only
        self.num_samples = opts.num_samples
        self.detailed_modeling = opts.detailed_modeling
        self.prefetch_decisions = {}
        self.exec_file = opts.exec_file
        self.report_delinq_loads_only = opts.report_delinq_loads_only

    def help_filters(self, option, opt, value, parser):
        sample_filter.usage()
        sys.exit(0)

def pow2(x):
    return int(math.pow(2, x))

def pow2_range(l, u):
    return map(pow2, range(l, u))

def default_range_func():
    return pow2_range(10, 24)

def open_sample_file(file_name, line_size):
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

def generate_sdist_hist(rdist_hist):
    hist = {}
    r2s = lrumodel.lru_sdist(rdist_hist)
    for (rdist, count) in rdist_hist.items():
        sdist = r2s[rdist]
        hist[sdist] = hist.get(sdist, 0) + count

    return hist

def rdist_hist_original(burst_hists):
    
    hist = {}

    for (pc_rdist_hist, pc_freq_hist, pc_corr_hist, pc_fwd_rdist_hist) in burst_hists:
        
        for (pc, rdist_hist) in pc_rdist_hist.items():
            for (rdist, count) in rdist_hist.items():
                hist[rdist] = hist.get(rdist, 0) + count

    return hist

def reduce_stride_hist(pc_stride_hist):
    
    hist = {}

    for (pc, stride_hist) in pc_stride_hist.items():
        
        for (stride, count) in stride_hist.items():
            if stride == 0 or count == 1: 
                continue
            
            if not hist.has_key(pc):
                hist[pc]= {}

            hist[pc][stride] = count

    return hist

def generate_per_pc_sdist_recurrence_hist(burst_hists):

    pc_sdist_hist = {}
    pc_recur_hist = {}
    pc_fwd_sdist_hist = {}

    for (pc_rdist_hist, pc_freq_hist, pc_corr_hist, pc_fwd_rdist_hist) in burst_hists:

        rdist_hist = rdist_hist_original(burst_hists)

        r2s = lrumodel.lru_sdist(rdist_hist)

        for (pc, rdist_hist) in pc_rdist_hist.items():

            if not pc in pc_sdist_hist:
                pc_sdist_hist[pc] = {}

            for (rdist, count) in rdist_hist.items():
                sd  = int(round(r2s[rdist]))
                pc_sdist_hist[pc][sd] = pc_sdist_hist[pc].get(sd, 0) + count

        for (pc, fwd_rdist_hist) in pc_fwd_rdist_hist.items():

            if not pc in pc_fwd_sdist_hist:
                pc_fwd_sdist_hist[pc] = {}

            for (rdist, count) in fwd_rdist_hist.items():
                sd  = int(round(r2s[rdist]))
                pc_fwd_sdist_hist[pc][sd] = pc_fwd_sdist_hist[pc].get(sd, 0) + count

    return [pc_sdist_hist, pc_fwd_sdist_hist]

def prefetchable_pcs(burst_hists, conf):

    sdist_fwdsdist_list = generate_per_pc_sdist_recurrence_hist(burst_hists)

    pc_sdist_hist = sdist_fwdsdist_list[0]

    pc_fwd_sdist_hist = sdist_fwdsdist_list[1]

    pref_pcs = []

    for (pc, sdist_hist) in pc_sdist_hist.items():
    
        if max(sdist_hist.keys()) > (float(conf.l1_size * 1024) / float(conf.line_size)):
            pref_pcs.append(pc)


    return [pref_pcs, pc_sdist_hist, pc_fwd_sdist_hist]

def build_global_prefetchable_pcs(global_prefetchable_pcs, pref_pcs):

    for pc in pref_pcs:
        if not pc in global_prefetchable_pcs:
            global_prefetchable_pcs.append(pc);

def build_global_pc_corr_hist(global_pc_corr_hist, pc_corr_hist):

    for (start_pc, corr_hist) in pc_corr_hist.items():
        if start_pc in global_pc_corr_hist:
            for (end_pc, count) in corr_hist.items():
                global_pc_corr_hist[start_pc][end_pc] = global_pc_corr_hist[start_pc].get(end_pc, 0) + count
        else:
            global_pc_corr_hist[start_pc] = {} 
            for (end_pc, count) in corr_hist.items():
                global_pc_corr_hist[start_pc][end_pc] = count


def build_global_pc_fwd_sdist_hist(global_pc_fwd_sdist_hist, pc_fwd_sdist_hist, global_pc_sdist_hist, pc_sdist_hist):

    for (pc, fwd_sdist_hist) in pc_fwd_sdist_hist.items():
        if pc in global_pc_fwd_sdist_hist:
            for (sdist, count) in fwd_sdist_hist.items():
                global_pc_fwd_sdist_hist[pc][sdist] = global_pc_fwd_sdist_hist[pc].get(sdist, 0) + count
        else:
            global_pc_fwd_sdist_hist[pc] = {} 
            for (sdist, count) in fwd_sdist_hist.items():
                global_pc_fwd_sdist_hist[pc][sdist] = count

    for (pc, sdist_hist) in pc_sdist_hist.items():
        if pc in global_pc_sdist_hist:
            for (sdist, count) in sdist_hist.items():
                global_pc_sdist_hist[pc][sdist] = global_pc_sdist_hist[pc].get(sdist, 0) + count
        else:
            global_pc_sdist_hist[pc] = {} 
            for (sdist, count) in sdist_hist.items():
                global_pc_sdist_hist[pc][sdist] = count


def build_global_pc_line_sdist_hist(global_pc_line_hist, global_line_sdist_hist, pc_line_hist, line_sdist_hist ):

    for (pc, line_hist) in pc_line_hist.items():
        if pc in global_pc_line_hist:
            for (line, count) in line_hist.items():
                global_pc_line_hist[pc][line] = global_pc_line_hist[pc].get(line, 0) + count
        else:
            global_pc_line_hist[pc] = {} 
            for (line, count) in line_hist.items():
                global_pc_line_hist[pc][line] = count

    for (line, sdist_hist) in line_sdist_hist.items():
        if line in global_line_sdist_hist:
            for (sdist, count) in sdist_hist.items():
                global_line_sdist_hist[line][sdist] = global_line_sdist_hist[line].get(sdist, 0) + count
        else:
            global_line_sdist_hist[line] = {} 
            for (sdist, count) in sdist_hist.items():
                global_line_sdist_hist[line][sdist] = count


def build_full_pc_stride_hist(burst_hists, full_pc_stride_hist):

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_smptrace_hist) in burst_hists:
        
        pc_l = pc_stride_hist.keys()

        for pc in pc_l:
            if pc in full_pc_stride_hist:

                for stride in pc_stride_hist[pc].keys():
                    
                    if stride in full_pc_stride_hist[pc].keys():
                        full_pc_stride_hist[pc][stride] += pc_stride_hist[pc][stride]
                    else:
                        full_pc_stride_hist[pc][stride] = pc_stride_hist[pc][stride]
                        
            else:

                full_pc_stride_hist[pc] = {}
                for stride in pc_stride_hist[pc].keys():
                    full_pc_stride_hist[pc][stride] = pc_stride_hist[pc][stride]

def is_nontemporal(pc, global_pc_corr_hist, global_pc_fwd_sdist_hist, conf):

    checked_pcs = []

    pending_pcs = [(pc, 1.0)]

    pc_arr_map = []

    for pc_prob_tup in pending_pcs:
        
        p_pc = pc_prob_tup[0]
        prob = float(pc_prob_tup[1])

        if p_pc in checked_pcs:
            continue

        if p_pc not in global_pc_corr_hist:
            continue

        total_count = sum(global_pc_corr_hist[p_pc].values())

        for end_pc in global_pc_corr_hist[p_pc].keys():
            
            if end_pc in checked_pcs:
                continue

            if end_pc not in pending_pcs:
                
                end_pc_prob = float(float(global_pc_corr_hist[p_pc][end_pc]) / float(total_count))

                arrival_prob = float( end_pc_prob * prob)
                
                if arrival_prob >= 0.4:
                    pending_pcs.append((end_pc, arrival_prob))

#            pc_arr_map.append((p_pc, end_pc, arrival_prob))

        sdist_list = global_pc_fwd_sdist_hist[p_pc].keys()
            
        non_l1_sdist_list = filter(lambda x: x > (float(conf.l1_size * 1024) / float(conf.line_size)), sdist_list)
        
        if len(non_l1_sdist_list) > 0 and min(non_l1_sdist_list) < (float(conf.l3_size * 1024 )/ float(conf.line_size)):
            return False
        
        checked_pcs.append(p_pc)

#    print >> sys.stderr, "data flow"
#    for tup in pc_arr_map:
#        print >> sys.stderr, tup
    
    return True

def analyze_temporal_locality(pc, global_pc_fwd_sdist_hist, conf):

    if pc not in global_pc_fwd_sdist_hist:
        return 0 #maybe this should return 3 and not 0

    bypass_decision = 0

    fwd_sdist_list = global_pc_fwd_sdist_hist[pc].keys()

    l1_sdist_size = float(conf.l1_size * 1024) / float(conf.line_size)
    l2_sdist_size = float(conf.l2_size * 1024) / float(conf.line_size)
    l3_sdist_size = float(conf.l3_size * 1024) / float(conf.line_size)

    l2_sdist_list = filter(lambda x: x > l1_sdist_size and x <= l2_sdist_size, fwd_sdist_list)

    l3_sdist_list = filter(lambda x: x > l2_sdist_size and x <= l3_sdist_size, fwd_sdist_list)

    if len(l2_sdist_list) == 0:
        bypass_decision = bypass_decision + 2 # bypass l2

    if len(l3_sdist_list) == 0:
        bypass_decision = bypass_decision + 4 # bypass l2

    return bypass_decision

def generate_pref_pcs_info(global_prefetchable_pcs, global_pc_fwd_sdist_hist, global_pc_corr_hist, global_pc_sdist_hist, conf):

    cache_line_size = conf.line_size

    analysis_type = conf.analysis_type
    cyc_per_mop = conf.cyc_per_mop
    memory_latency = conf.memory_latency
    l3_latency = conf.l3_latency
    l2_latency = conf.l2_latency
    l1_latency = conf.l1_latency
    l3_size = conf.l3_size
    l2_size = conf.l2_size
    l1_size = conf.l1_size

    avg_mem_latency = memory_latency

    avg_iters = 0

    remove_pcs = []

    for pc in global_prefetchable_pcs:

        total_accesses = sum(global_pc_sdist_hist[pc].values())

        max_sdist = max(global_pc_sdist_hist[pc].keys())
        
        l1_misses = 0
        l2_misses = 0
        l3_misses = 0

        sdist_list = global_pc_sdist_hist[pc].items()

        l1_miss_sdist_list = filter(lambda (x,y): x > float(conf.l1_size * 1024 / conf.line_size), sdist_list)
        l2_miss_sdist_list = filter(lambda (x,y): x > float(conf.l2_size * 1024 / conf.line_size), sdist_list)
        l3_miss_sdist_list = filter(lambda (x,y): x > float(conf.l3_size * 1024 / conf.line_size), sdist_list)

        l1_misses = sum(map(lambda (x,y): y, l1_miss_sdist_list))

        l2_misses = sum(map(lambda (x,y): y, l2_miss_sdist_list))

        l3_misses = sum(map(lambda (x,y): y, l3_miss_sdist_list))

        ref_count = sum(map(lambda (x,y): y, sdist_list))

        l1_mr = float(float(l1_misses)/float(total_accesses)) 
        l2_mr = float(float(l2_misses)/float(total_accesses)) 
        l3_mr = float(float(l3_misses)/float(total_accesses)) 

        bypass_decision = analyze_temporal_locality(pc, global_pc_fwd_sdist_hist, conf)

        if bypass_decision > 0:
            print "%ld:%ld"%(pc, bypass_decision)
        

def main():
    conf = Conf()

    listing = os.listdir(conf.path)

    cache_size_range = default_range_func()

    win_count = 0

    mr = {}

    mr_w_pf = {}

    pref_pcs_win = {}

    global_pc_fwd_sdist_hist = {}

    global_pc_sdist_hist = {}

    global_pc_corr_hist = {}

    global_prefetchable_pcs = []
    
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
            burst_hists = bypassutils.usf_read_events(usf_file,
                                                line_size=conf.line_size,
                                                filter=conf.filter)

        except IOError, e:
            continue

        usf_file.close()


        pref_pcs_sdist_list = prefetchable_pcs(burst_hists, conf)
        
        pref_pcs = pref_pcs_sdist_list[0]
        
        pc_sdist_hist = pref_pcs_sdist_list[1]
        
        pc_fwd_sdist_hist = pref_pcs_sdist_list[2]
        
        build_global_prefetchable_pcs(global_prefetchable_pcs, pref_pcs)
        
        pc_corr_hist = burst_hists[0][2]

        build_global_pc_corr_hist(global_pc_corr_hist, pc_corr_hist)

        build_global_pc_fwd_sdist_hist(global_pc_fwd_sdist_hist, pc_fwd_sdist_hist,global_pc_sdist_hist, pc_sdist_hist)
    
    generate_pref_pcs_info(global_prefetchable_pcs, global_pc_fwd_sdist_hist, global_pc_corr_hist, global_pc_sdist_hist, conf)

if __name__ == "__main__":
    main()

