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
import adjutils
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

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_adjp1_cl_rdist_hist, pc_adjm1_cl_rdist_hist) in burst_hists:
        
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


def rdist_hist_after_prefetching(burst_hists, pref_pcs):

    hist = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_adjp1_cl_rdist_hist, pc_adjm1_cl_rdist_hist) in burst_hists:
        
        for (pc, rdist_hist) in pc_rdist_hist.items():
            for (rdist, count) in rdist_hist.items():
                if pref_pcs.count(pc) == 0:
                    hist[rdist] = hist.get(rdist, 0) + count

    if len(hist) == 0:
        for (pc, rdist_hist) in pc_rdist_hist.items():
            for (rdist, count) in rdist_hist.items():
                    hist[rdist] = 0
    
    return hist

def generate_per_pc_sdist_recurrence_hist(burst_hists):

    pc_sdist_hist = {}
    pc_recur_hist = {}
    pc_fwd_sdist_hist = {}
    r2s = {}

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_adjp1_cl_rdist_hist, pc_adjm1_cl_rdist_hist) in burst_hists:

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

        for (pc, time_hist) in pc_time_hist.items():

            if not pc in pc_recur_hist:
                pc_recur_hist[pc] = {}

            for (recur, count) in time_hist.items():

                if not recur in r2s:
                    recur_c = min(r2s.keys(), key=lambda k: abs(k - recur))
                    recur = recur_c

                sd  = int(round(r2s[recur]))
                pc_recur_hist[pc][sd] = pc_recur_hist[pc].get(sd, 0) + count

    return [pc_sdist_hist, pc_recur_hist, pc_fwd_sdist_hist, r2s]

def prefetchable_pcs(burst_hists, conf):

    sdist_recur_list = generate_per_pc_sdist_recurrence_hist(burst_hists)

    pc_sdist_hist = sdist_recur_list[0]

    pc_recur_hist = sdist_recur_list[1]

    pc_fwd_sdist_hist = sdist_recur_list[2]

    r2s = sdist_recur_list[3]

    pref_pcs = []

    for (pc, sdist_hist) in pc_sdist_hist.items():
    
        if max(sdist_hist.keys()) > (float(conf.l1_size * 1024) / float(conf.line_size)):

            #in case of a dangling pointer, there "may" be no entry in pc_recur_hist 
            if pc in pc_recur_hist:
                max_recur = max(pc_recur_hist[pc].keys())

                if  max_recur < float(float(0.75) * float(conf.l1_size * 1024 / conf.line_size)):
                    pref_pcs.append(pc)
                else:
                    #need some clear strategy for nested loops, where outer loop's recurrence may be larger than L1 cache
                    total_recur_count = sum(pc_recur_hist[pc].itervalues()) 
                    max_recur_freq = float(float(pc_recur_hist[pc][max_recur])/float(total_recur_count) )

                    if max_recur_freq < 0.5:
                        pref_pcs.append(pc)
            else:
                pref_pcs.append(pc)


    return [pref_pcs, pc_sdist_hist, pc_recur_hist, pc_fwd_sdist_hist, r2s]

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


def build_global_pc_fwd_sdist_recur_hist(global_pc_fwd_sdist_hist, global_pc_recur_hist, pc_fwd_sdist_hist, pc_recur_hist, global_pc_sdist_hist, pc_sdist_hist):

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


    for (pc, recur_hist) in pc_recur_hist.items():
        if pc in global_pc_recur_hist:
            for (recur, count) in recur_hist.items():
                global_pc_recur_hist[pc][recur] = global_pc_recur_hist[pc].get(recur, 0) + count
        else:
            global_pc_recur_hist[pc] = {} 
            for (recur, count) in recur_hist.items():
                global_pc_recur_hist[pc][recur] = count


def build_global_pc_adj_mr_hist(r2s, conf, global_pc_adjp1_mr_hist, pc_adjp1_cl_rdist_hist, global_pc_adjm1_mr_hist, pc_adjm1_cl_rdist_hist, pc_rdist_hist):
    
#    ref_count = 0
#    for (pc, rdist_hist) in pc_rdist_hist.items():
#        ref_count += sum(rdist_hist.values())

    for (pc, adjp1_cl_rdist_hist) in pc_adjp1_cl_rdist_hist.items():
        
        sdist_hist = {}
        ref_count = 0
        
        for (rdist, count) in adjp1_cl_rdist_hist.items():
    
            if not rdist in r2s:
                rdist_c = min(r2s.keys(), key=lambda k: abs(k - rdist))
                rdist = rdist_c

            sd  = int(round(r2s[rdist]))

            if sd in sdist_hist.keys():
                sdist_hist[sd] = sdist_hist.get(sd, 0) + count
            else:
                sdist_hist[sd] = count

            ref_count += count

        [adjp1_l1mr, adjp1_l2mr, adjp1_l3mr] = get_pc_adj_miss_ratio(pc, sdist_hist, ref_count, conf)

        if not adjp1_l1mr:
            continue
        
        if pc in global_pc_adjp1_mr_hist.keys():
            global_pc_adjp1_mr_hist[pc][0].append(adjp1_l1mr)
            global_pc_adjp1_mr_hist[pc][1].append(adjp1_l2mr)
            global_pc_adjp1_mr_hist[pc][2].append(adjp1_l3mr)
        else:
            global_pc_adjp1_mr_hist[pc] = {0: [adjp1_l1mr]} 
            global_pc_adjp1_mr_hist[pc].update({1: [adjp1_l2mr]})
            global_pc_adjp1_mr_hist[pc].update({2: [adjp1_l3mr]})

    for (pc, adjm1_cl_rdist_hist) in pc_adjm1_cl_rdist_hist.items():
        
        sdist_hist = {}
        ref_count = 0

        for (rdist, count) in adjm1_cl_rdist_hist.items():
    
            if not rdist in r2s:
                rdist_c = min(r2s.keys(), key=lambda k: abs(k - rdist))
                rdist = rdist_c

            sd  = int(round(r2s[rdist]))

            if sd in sdist_hist.keys():
                sdist_hist[sd] = sdist_hist.get(sd, 0) + count
            else:
                sdist_hist[sd] = count

            ref_count += count

        [adjm1_l1mr, adjm1_l2mr, adjm1_l3mr] = get_pc_adj_miss_ratio(pc, sdist_hist, ref_count, conf)

        if not adjm1_l1mr:
            continue

        if pc in global_pc_adjm1_mr_hist.keys() and global_pc_adjm1_mr_hist[pc]:
            global_pc_adjm1_mr_hist[pc][0].append(adjm1_l1mr)
            global_pc_adjm1_mr_hist[pc][1].append(adjm1_l2mr)
            global_pc_adjm1_mr_hist[pc][2].append(adjm1_l3mr)
        else:
            global_pc_adjm1_mr_hist[pc] = {0: [adjm1_l1mr]}
            global_pc_adjm1_mr_hist[pc].update({1: [adjm1_l2mr]})
            global_pc_adjm1_mr_hist[pc].update({2: [adjm1_l3mr]})


def get_pc_adj_miss_ratio(pc, sdist_hist, ref_count, conf):

    adj_sdist_list = sdist_hist.items()
    
    adj_mr = []
    
    l1_miss_sdist_list = filter(lambda (x,y): x > float(conf.l1_size * 1024 / conf.line_size), adj_sdist_list)
    l2_miss_sdist_list = filter(lambda (x,y): x > float(conf.l2_size * 1024 / conf.line_size), adj_sdist_list)
    l3_miss_sdist_list = filter(lambda (x,y): x > float(conf.l3_size * 1024 / conf.line_size), adj_sdist_list)
    
    l1_misses = sum(map(lambda (x,y): y, l1_miss_sdist_list))
    
    l2_misses = sum(map(lambda (x,y): y, l2_miss_sdist_list))
    
    l3_misses = sum(map(lambda (x,y): y, l3_miss_sdist_list))

    l1_mr = float(float(l1_misses)/float(ref_count)) 
    l2_mr = float(float(l2_misses)/float(ref_count)) 
    l3_mr = float(float(l3_misses)/float(ref_count)) 

    adj_mr = [l1_mr, l2_mr, l3_mr]
    
    return adj_mr

def comp_global_pc_adj_mr(conf, pc, global_pc_adjp1_mr_hist, global_pc_adjm1_mr_hist):

    if pc in global_pc_adjp1_mr_hist.keys():
        
        adjp1_l1mr = float(sum(global_pc_adjp1_mr_hist[pc][0])/len(global_pc_adjp1_mr_hist[pc][0]))
        adjp1_l2mr = float(sum(global_pc_adjp1_mr_hist[pc][1])/len(global_pc_adjp1_mr_hist[pc][1]))
        adjp1_l3mr = float(sum(global_pc_adjp1_mr_hist[pc][2])/len(global_pc_adjp1_mr_hist[pc][2]))

        del global_pc_adjp1_mr_hist[pc][0]
        del global_pc_adjp1_mr_hist[pc][1]
        del global_pc_adjp1_mr_hist[pc][2]
        
        global_pc_adjp1_mr_hist[pc][0] = adjp1_l1mr
        global_pc_adjp1_mr_hist[pc][1] = adjp1_l2mr
        global_pc_adjp1_mr_hist[pc][2] = adjp1_l3mr
        
    else:
        global_pc_adjp1_mr_hist[pc] = {0: 0.0, 1: 0.0, 2: 0.0}

    if pc in global_pc_adjm1_mr_hist.keys():
        
        adjm1_l1mr = float(sum(global_pc_adjm1_mr_hist[pc][0])/len(global_pc_adjm1_mr_hist[pc][0]))
        adjm1_l2mr = float(sum(global_pc_adjm1_mr_hist[pc][1])/len(global_pc_adjm1_mr_hist[pc][1]))
        adjm1_l3mr = float(sum(global_pc_adjm1_mr_hist[pc][2])/len(global_pc_adjm1_mr_hist[pc][2]))

        del global_pc_adjm1_mr_hist[pc][0]
        del global_pc_adjm1_mr_hist[pc][1]
        del global_pc_adjm1_mr_hist[pc][2]

        global_pc_adjm1_mr_hist[pc][0] = adjm1_l1mr
        global_pc_adjm1_mr_hist[pc][1] = adjm1_l2mr
        global_pc_adjm1_mr_hist[pc][2] = adjm1_l3mr
        
    else:
        global_pc_adjm1_mr_hist[pc] = {0: 0.0, 1: 0.0, 2: 0.0}

def build_full_pc_stride_hist(burst_hists, full_pc_stride_hist):

    for (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_adjp1_cl_rdist_hist, pc_adjm1_cl_rdist_hist) in burst_hists:
        
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

def generate_pref_pcs_info(global_prefetchable_pcs, global_pc_fwd_sdist_hist, global_pc_recur_hist, full_pc_stride_hist, global_pc_corr_hist, global_pc_sdist_hist, global_pc_adjp1_mr_hist, global_pc_adjm1_mr_hist, conf):

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

    reduced_full_pc_stride_hist = reduce_stride_hist(full_pc_stride_hist)

    for pc in global_prefetchable_pcs:

        if not pc in reduced_full_pc_stride_hist.keys():
            continue

#        if not pc in global_pc_corr_hist.keys():
#            continue

        pf_type = 'pf'

        total_accesses = sum(global_pc_sdist_hist[pc].values())

#        non_l1_accesses = 0

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

#        for (sdist, count) in global_pc_sdist_hist[pc].items():
#            if sdist > float(conf.l1_size * 1024 / conf.line_size):
#                l1_misses += count
#            elif sdist > float(conf.l2_size * 1024 / conf.line_size):
#                l2_misses += count
#            elif sdist > float(conf.l3_size * 1024 / conf.line_size):
#                l3_misses += count
            
        l1_mr = float(float(l1_misses)/float(total_accesses)) 
        l2_mr = float(float(l2_misses)/float(total_accesses)) 
        l3_mr = float(float(l3_misses)/float(total_accesses)) 

        if conf.detailed_modeling == 1:
#            if l3_mr < 0.005:
#               if l2_mr < 0.03:
#                   if l1_mr < 0.1:
#                       continue
            cb_score = float(1)/float(avg_mem_latency)
            if l1_mr < cb_score and l3_mr < 0.005:
                print >> sys.stderr, "\ncb-ignored %lx" % (pc)
                print >> sys.stderr, "L1 MR %lf%%, L2 MR %lf%%, L3_MR %lf%%, -- %s: dataset size: %lf MB"%(l1_mr, l2_mr, l3_mr, hex(pc), float(max_sdist * conf.line_size / (1024*1024)))
                continue

            if l1_mr >= cb_score and conf.report_delinq_loads_only == 1:
                print pc, l1_mr

            if conf.report_delinq_loads_only == 1:
                continue
            

        if analysis_type == "aggr" and pc in global_pc_fwd_sdist_hist.keys():

            sdist_list = global_pc_fwd_sdist_hist[pc].keys()

            non_l1_sdist_list = filter(lambda x: x > float(conf.l1_size * 1024 / conf.line_size), sdist_list)

            #considering L3$ size == 6MB (98304 cache lines)
            if len(non_l1_sdist_list) == 0 or min(non_l1_sdist_list) > (conf.l3_size * 1024):
                pf_type = 'nta'
        
        if analysis_type == "cons":
            isnontemporal = False
            isnontemporal = is_nontemporal(pc, global_pc_corr_hist, global_pc_fwd_sdist_hist, conf)
            if isnontemporal:
                pf_type = 'nta'


        sorted_x = sorted(reduced_full_pc_stride_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

        max_stride = sorted_x[0][0] 
        max_count = sorted_x[0][1]

        total_stride_count = sum(full_pc_stride_hist[pc].itervalues())

        max_stride_region_count = 0
        max_stride_region = math.floor(float(max_stride) / float(cache_line_size))
                    
        for s,c in full_pc_stride_hist[pc].items():
            
            if math.floor(float(s) / float(cache_line_size)) == max_stride_region:
                max_stride_region_count += c

        print >> sys.stderr,"\n\n"
        print >> sys.stderr,"Stride %lu"%(pc)

        comp_global_pc_adj_mr(conf, pc, global_pc_adjp1_mr_hist, global_pc_adjm1_mr_hist)

        adjp1_l1mr = global_pc_adjp1_mr_hist[pc][0]
        adjp1_l2mr = global_pc_adjp1_mr_hist[pc][1]
        adjp1_l3mr = global_pc_adjp1_mr_hist[pc][2]

        adjm1_l1mr = global_pc_adjm1_mr_hist[pc][0]
        adjm1_l2mr = global_pc_adjm1_mr_hist[pc][1]
        adjm1_l3mr = global_pc_adjm1_mr_hist[pc][2]

        print >> sys.stderr,"adjp1 - L1 MR: %lf, L2 MR: %lf, L3 MR: %lf"%(adjp1_l1mr, adjp1_l2mr, adjp1_l3mr) 
        print >> sys.stderr,"adjm1 - L1 MR: %lf, L2 MR: %lf, L3 MR: %lf"%(adjm1_l1mr, adjm1_l2mr, adjm1_l3mr)

        max_stride_region_freq = float(float(max_stride_region_count) / float(total_stride_count))

        if max_stride_region_freq < float(0.7):
            remove_pcs.append(pc)

            if conf.all_delinq_loads:
                if isnontemporal:
                    pf_type = "ptrnta"
                else:
                    pf_type = "ptr"
            print >> sys.stderr, "irregular strided load (L1 MR %lf%%, L2 MR %lf%%, L3_MR %lf%%, max stride region ratio %lf -- %s): dataset size: %lf MB"%(l1_mr, l2_mr, l3_mr, 
                    max_stride_region_freq, hex(pc),  float(max_sdist * conf.line_size / (1024*1024)) )

            print >> sys.stderr, "pc: %lx   freq-stride: %ld   freq-stride-region: %ld   prob: %lf"%(pc, max_stride, max_stride_region, max_stride_region_freq)

            more_stride_offsets = ""
            
            cb_factor = 20 #float(1/avg_mem_latency)

            print >> sys.stderr, "cb_factor %lf"%(cb_factor)

            if adjp1_l1mr > cb_factor:
                more_stride_offsets = more_stride_offsets+",64"
            if adjm1_l1mr > cb_factor:
                more_stride_offsets = more_stride_offsets+",-64"

            max_stride_region_offset = int(max_stride_region * cache_line_size)


            stride_offsets = more_stride_offsets.split(",")
#            if max_stride_region < 3 and max_stride_region > -3 and max_stride_region_freq > 0.1 and max_stride_region != 0 and str(max_stride_region_offset) not in stride_offsets:
#                more_stride_offsets = str(max_stride_region_offset)+more_stride_offsets

            for i in range (1, len(sorted_x)-1):
                if i > 5:
                    continue
                stride = sorted_x[i][0] 
                count = sorted_x[i][1]

                stride_region_count = 0
                stride_region = math.floor(float(stride) / float(cache_line_size))
                    
                if stride_region == 0:
                    continue

                for s,c in full_pc_stride_hist[pc].items():
            
                    if math.floor(float(s) / float(cache_line_size)) == stride_region:
                        stride_region_count += c
                
                stride_region_freq = float(float(stride_region_count) / float(total_stride_count))
        
                print >> sys.stderr, "pc: 0x%lx   freq-stride: %ld   freq-stride-region: %ld   prob: %lf"%(pc, stride, stride_region, stride_region_freq)


#                if stride_region_freq > 0.1 and stride_region != 0:
#                    stride_offset = int(stride_region * cache_line_size)
#                    stride_offsets = more_stride_offsets.split(",")

#                    if not str(stride_offset) in stride_offsets and stride_offset != max_stride_region_offset and stride_offset in [-128,-64,64,128]:
#                        more_stride_offsets = more_stride_offsets+","+str(stride_offset)
                    
            if more_stride_offsets:
                if more_stride_offsets[0] == ',':
                    more_stride_offsets = more_stride_offsets[1:]
                print "0x%lx:adj:%s"%(pc, more_stride_offsets)

            #add prefetch decision to central data structure
            pref_param = PrefParams(pc, pf_type, 0, l1_mr, l2_mr, l3_mr)
            conf.prefetch_decisions[pc] = pref_param

            continue

        print >> sys.stderr, "regular strided load (L1 MR %lf%%, L2 MR %lf%%, L3_MR %lf%%, max stride region ratio %lf -- %s): dataset size: %lf MB"%(l1_mr, l2_mr, l3_mr, 
                    float(float(max_stride_region_count) / float(total_stride_count)), hex(pc),  float(max_sdist * conf.line_size / (1024*1024)) )
        

        min_r = min(global_pc_recur_hist[pc].keys())

        stride = max_stride

#        if (abs(stride) * max_count) <= cache_line_size:

#            adj_pref_off=""
#            if adjp1_l1mr > 0:
#                adj_pref_off = "64"
#            if adjm1_l1mr > 0:
#                if adj_pref_off:
#                    adj_pref_off = adj_pref_off +","
#                    adj_pref_off = adj_pref_off +"-64"

#            if len(adj_pref_off) > 1:
#                print"0x%lx:adj:%s"%(pc, adj_pref_off)

#            continue

        
#        if max(global_pc_sdist_hist[pc].keys()) > (l3_size * 1024 / cache_line_size):
        avg_mem_latency = memory_latency 
#        elif max(global_pc_sdist_hist[pc].keys()) > (l2_size * 1024 / cache_line_size) and max(global_pc_sdist_hist[pc].keys()) < (l3_size * 1024 / cache_line_size):
#            avg_mem_latency = l3_latency 
#        elif max(global_pc_sdist_hist[pc].keys()) > (l2_size * 1024 / cache_line_size) and max(global_pc_sdist_hist[pc].keys()) < (l2_size * 1024 / cache_line_size):
#            avg_mem_latency = l2_latency

        total_count = sum(global_pc_fwd_sdist_hist[pc].values())

        sorted_x = sorted(global_pc_recur_hist[pc].iteritems(), key=operator.itemgetter(1), reverse=True)

        weight = 0
        avg_r = 0

        for r, c in sorted_x:
            avg_r += int(r) * int(c)
            weight += int(c)

        avg_r = round(float(avg_r)/ float(weight))

        min_r = sorted_x[0][0]

        if min_r == 0:
            min_r = 1

        if avg_r == 0:
            avg_r = 1
            

        recur_freq = sorted(global_pc_recur_hist[pc].values(), reverse=True) 
        recur_freq_thr = 200 #int(recur_freq[0])/6
        recur_freq_out_loop = filter(lambda y: y > recur_freq_thr, recur_freq)
        recur_freq_in_loop = filter(lambda y: y <= recur_freq_thr, recur_freq)

        loop_recur_freq = sum(recur_freq_in_loop)
        loop_reach_freq = sum(recur_freq_out_loop)

        if loop_reach_freq == 0:
            loop_reach_freq = 1
 
        avg_iters = float(float(loop_recur_freq)/float(loop_reach_freq))

        if avg_iters == 0:
            avg_iters = 1

        # cycles/memory-operation (without h/w pf, with h/w pf)
        # gcc-166 3.74, 3.5 (1.3 works best, 3.0)
        # libquantum XXX, 9.2 (2 works best, 7.0)
        # lbm XXX, 5.4 (1.5 works best, 5.0)
        # mcf XXX, 21.2 (12 works best, 18.0)
        # omnetpp XXX, 8.7 (6 works best, 7.0)
        # soplex 7.6, 6 (5 works best, 5.7)
        # astar XXX, 3.6 (3.2 works best, 3.2)
	# cigar-60k 18.4 (9 works, 9)
	# xalan XXX 2.99 (2.8)

        if abs(stride) < cache_line_size:

            no_iters = int(round(float(cache_line_size) / float(abs(stride)) )) - 1

            if no_iters == 0:
                no_iters = 1

            pd = math.ceil(float(avg_mem_latency) / float(avg_r * cyc_per_mop * no_iters ))

            if pd == 0:
                pd = 1 

            if stride < 0:
                pd = -1 * pd

            stride = cache_line_size

            sd = cache_line_size * pd

#############################################################

#            if full_pc_stride_hist[pc][stride] < pd:
#            if (avg_iters/2) < pd:
#                pd = math.ceil(float(avg_iters)/float(2))
#                sd = cache_line_size * pd #2

#############################################################

        else:
            
            no_iters = 1

            pd = math.ceil(float(avg_mem_latency) / float(avg_r * cyc_per_mop * no_iters))

            if pd == 0:
                pd = 1 

            if stride < 0:
                pd = -1 * pd

            sd = stride * pd

#############################################################

#            if full_pc_stride_hist[pc][stride] < pd:
        if conf.detailed_modeling == 1:
            if (avg_iters/2) < pd:
                pd = math.ceil(float(avg_iters)/float(2)) 
                sd = stride * pd 
            
#############################################################

        print >> sys.stderr, pc
        print >> sys.stderr, total_count
        print >> sys.stderr, stride, pd, sd, avg_iters
        print >> sys.stderr, "\n\n"
#        print >> sys.stderr, recur_freq

#        print >> sys.stderr, "\n\n\n"
                
#        print >> sys.stderr, full_pc_stride_hist[pc]

#        if conf.detailed_modeling == 1:

#            if isnontemporal and ((pd * 2) < (avg_iters / 2)):
#                sd = sd * 2
#                print >> sys.stderr, "stride doubled for non temporal access (load from DRAM)"
    
        #add prefetch decision to central data structure
        pref_param = PrefParams(pc, pf_type, pd, l1_mr, l2_mr, l3_mr)
        conf.prefetch_decisions[pc] = pref_param
        
#        if total_count > 50:
        print"0x%lx:%s:%d"%(pc, pf_type, int(sd))
        
        adj_pref_off=""
        if adjp1_l1mr > 0 and sd != 64:
            adj_pref_off = "64"
        if adjm1_l1mr > 0 and sd != -64:
            if adj_pref_off:
                adj_pref_off = adj_pref_off +","
                adj_pref_off = adj_pref_off +"-64"

        if len(adj_pref_off) > 1:
            print"0x%lx:adj:%s"%(pc, adj_pref_off)

def main():
    conf = Conf()

    listing = os.listdir(conf.path)

    cache_size_range = default_range_func()

    win_count = 0

    mr = {}

    mr_w_pf = {}

    pref_pcs_win = {}

    full_pc_stride_hist = {}

    global_pc_fwd_sdist_hist = {}

    global_pc_sdist_hist = {}

    global_pc_corr_hist = {}

    global_pc_recur_hist = {}
    
    global_prefetchable_pcs = []
    
    global_pc_smptrace_hist = {}

    global_pc_adjp1_mr_hist = {} 
    
    global_pc_adjm1_mr_hist = {}

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
            burst_hists = adjutils.usf_read_events(usf_file, infile,
                                                line_size=conf.line_size,
                                                filter=conf.filter)

        except IOError, e:
            continue

#        usf_file.close()


        (pc_rdist_hist, pc_stride_hist, pc_freq_hist, pc_time_hist, pc_corr_hist, pc_fwd_rdist_hist, pc_adjp1_cl_rdist_hist, pc_adjm1_cl_rdist_hist) = burst_hists[-1]

        pref_pcs_sdist_recur_list = prefetchable_pcs(burst_hists, conf)
        
        pref_pcs = pref_pcs_sdist_recur_list[0]
        
        pc_sdist_hist = pref_pcs_sdist_recur_list[1]
        
        pc_recur_hist = pref_pcs_sdist_recur_list[2]
            
        pc_fwd_sdist_hist = pref_pcs_sdist_recur_list[3]
        
        r2s = pref_pcs_sdist_recur_list[4]
        
        build_global_prefetchable_pcs(global_prefetchable_pcs, pref_pcs)
        
        pc_corr_hist = burst_hists[0][4]

        build_global_pc_corr_hist(global_pc_corr_hist, pc_corr_hist)

        build_global_pc_fwd_sdist_recur_hist(global_pc_fwd_sdist_hist, global_pc_recur_hist, pc_fwd_sdist_hist, pc_recur_hist, global_pc_sdist_hist, pc_sdist_hist)

        build_global_pc_adj_mr_hist(r2s, conf, global_pc_adjp1_mr_hist, pc_adjp1_cl_rdist_hist, global_pc_adjm1_mr_hist, pc_adjm1_cl_rdist_hist, pc_rdist_hist)

        build_full_pc_stride_hist(burst_hists, full_pc_stride_hist)

        pc_smptrace_hist = burst_hists[0][6]

        ins_trace_analysis.add_trace_to_global_pc_smptrace_hist(global_pc_smptrace_hist, pc_smptrace_hist)


    generate_pref_pcs_info(global_prefetchable_pcs, global_pc_fwd_sdist_hist, global_pc_recur_hist, full_pc_stride_hist, global_pc_corr_hist, global_pc_sdist_hist, global_pc_adjp1_mr_hist, global_pc_adjm1_mr_hist, conf)

    for pc in conf.prefetch_decisions.keys():
        pref_param = conf.prefetch_decisions[pc]
        print >> sys.stderr, "pc: %lx"%(pc)
        print >> sys.stderr, "pf_type "+pref_param.pf_type


if __name__ == "__main__":
    main()

