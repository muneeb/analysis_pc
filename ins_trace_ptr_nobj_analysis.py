#!/usr/bin/python

import string
import sys
import re
import operator
import os
import pyusf
import utils

import static_BB_cfg
import disassm

import Queue
import math

from collections import deque

def is_nested_object(delinq_load_addr, update_addr, cfg):

    base_reg_id_delinq_load = cfg.ins_base_reg_dict[delinq_load_addr]
    base_reg_id_update_instr = cfg.ins_base_reg_dict[update_addr]

    if base_reg_id_delinq_load != base_reg_id_update_instr:
        return True
    
    return False

def add_trace_to_global_pc_smptrace_hist(global_pc_smptrace_hist, pc_smptrace_dict):

    for pc in pc_smptrace_dict.keys():
        for time in pc_smptrace_dict[pc].keys():
            smptrace = pc_smptrace_dict[pc][time]
            utils.addto_pc_smptrace_hist(global_pc_smptrace_hist, pc, time, smptrace)

    return

def add_to_pc_stride_hist(pc_stride_hist, global_pc_stride_hist):

    pc_l = pc_stride_hist.keys()

    for pc in pc_l:
        if pc in global_pc_stride_hist:

            for stride in pc_stride_hist[pc].keys():
                    
                if stride in global_pc_stride_hist[pc].keys():
                    global_pc_stride_hist[pc][stride] += pc_stride_hist[pc][stride]
                else:
                    global_pc_stride_hist[pc][stride] = pc_stride_hist[pc][stride]
                        
        else:

            global_pc_stride_hist[pc] = {}
            for stride in pc_stride_hist[pc].keys():
                global_pc_stride_hist[pc][stride] = pc_stride_hist[pc][stride]


def update_pc_weight_hist(pc_mem_dis_weights_dict, pc, base_reg, dis):
    
    if pc in pc_mem_dis_weights_dict.keys():
        if base_reg in pc_mem_dis_weights_dict[pc].keys():
            if not dis in pc_mem_dis_weights_dict[pc][base_reg].keys():
                pc_mem_dis_weights_dict[pc][base_reg][dis] = 0
        else:
            pc_mem_dis_weights_dict[pc][base_reg] = {}
            pc_mem_dis_weights_dict[pc][base_reg][dis] = 0
    else:
        pc_mem_dis_weights_dict[pc] = {}
        pc_mem_dis_weights_dict[pc][base_reg] = {}
        pc_mem_dis_weights_dict[pc][base_reg][dis] = 0

    pc_mem_dis_weights_dict[pc][base_reg][dis] += 1


#def detect_BBs_in_loop():


def record_time_to_update(delinq_load_addr, update_addr, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, BBs_in_loop, delinq_loads_update_addr, prefetch_decisions, conf):

    if not delinq_load_addr in trace_q:
        return

    fwd_score = 0
    fwd_delinq_loads = 0

    BB_addr = static_BB_cfg.discover_BB_for_address(update_addr, cfg.BB_dict)

    while trace_q:

        if not BB_addr in BBs_in_loop:
            BBs_in_loop.append(BB_addr)

        pc_in_trace =  trace_q.popleft()

        if pc_in_trace == 0:
            return

        if pc_in_trace == delinq_load_addr:
            break

        if pc_in_trace in cfg.ins_tags_dict:
            if pc_in_trace in conf.all_delinq_loads_list and prefetch_decisions:
                if prefetch_decisions[pc_in_trace].l3_mr >= 0.01:
                    fwd_delinq_loads += 1
                elif prefetch_decisions[pc_in_trace].l2_mr >= 0.05:
                    fwd_delinq_loads += 1
                elif prefetch_decisions[pc_in_trace].l1_mr >= 0.2:
                    fwd_delinq_loads += 1


        fwd_score += 1
        
        BB_addr = static_BB_cfg.discover_BB_for_address(pc_in_trace, cfg.BB_dict)
        
        if BB_addr == None:
            cfg = disassm.get_func_disassm(cfg.exec_file, pc_in_trace)
            BB_addr = static_BB_cfg.discover_BB_for_address(pc_in_trace, cfg.BB_dict)
            if BB_addr == None:
                return

    record_update_time(delinq_load_addr, fwd_score, time_to_update_dict, fwd_delinq_loads, delinq_loads_till_update)

            
def record_update_time(delinq_load_addr, score, pointer_update_time_dict, delinq_loads_count, delinq_loads_dict):

    if delinq_load_addr in pointer_update_time_dict:
        if score in pointer_update_time_dict[delinq_load_addr].keys():
            pointer_update_time_dict[delinq_load_addr][score] += 1
        else:
            pointer_update_time_dict[delinq_load_addr][score] = 1
    else:
        pointer_update_time_dict[delinq_load_addr] = {}
        pointer_update_time_dict[delinq_load_addr][score] = 1

    if delinq_loads_count in delinq_loads_dict:
        delinq_loads_dict[delinq_loads_count] += 1
    else:
        delinq_loads_dict[delinq_loads_count] = 1

def record_update_addr(delinq_load_addr, update_addr, delinq_loads_update_addr):
    
    if delinq_load_addr in delinq_loads_update_addr:
        if not update_addr in delinq_loads_update_addr[delinq_load_addr]:
            delinq_loads_update_addr[delinq_load_addr].append(update_addr)
    else:
        delinq_loads_update_addr[delinq_load_addr] = [update_addr]


def record_update_trace(precomp_chain_t, update_trace_dict):
    
    if precomp_chain_t in update_trace_dict:
        update_trace_dict[precomp_chain_t] += 1
    else:
        update_trace_dict[precomp_chain_t] = 1
   
def dominant_update_trace(update_trace_dict):
    
    total_traces = sum(update_trace_dict.values())
    update_trace_weights = update_trace_dict.items()
    update_trace_weights = sorted(update_trace_weights, key=operator.itemgetter(1), reverse=True)
    if not update_trace_weights:
        return None

    freq_update_trace_weight = update_trace_weights[0]
    freq_update_trace_t = freq_update_trace_weight[0]
    trace_freq = float(freq_update_trace_weight[1])/float(total_traces)
    print >> sys.stderr, "freq update trace - trace fre: %lf"%(trace_freq)
    for pc in freq_update_trace_t:
        print >> sys.stderr, "%lx"%(pc)

    print >> sys.stderr, ""
    return freq_update_trace_t
    

def is_indirect_addr(update_trace_t, global_pc_stride_hist, cfg):

    ptr_update_pc = update_trace_t[-1]
    
    if not ptr_update_pc in global_pc_stride_hist:
        return (False, 0)
    
    pc_stride_hist = global_pc_stride_hist[ptr_update_pc]

    sorted_x = sorted(pc_stride_hist.iteritems(), key=operator.itemgetter(1), reverse=True)

    max_stride = sorted_x[0][0] 
    max_count = sorted_x[0][1]

    total_stride_count = sum(global_pc_stride_hist[ptr_update_pc].itervalues())

    max_stride_region_count = 0
    max_stride_region = math.floor(float(max_stride) / float(64))
                    
    for s,c in global_pc_stride_hist[ptr_update_pc].items():
            
        if math.floor(float(s) / float(64)) == max_stride_region:
            max_stride_region_count += c

    print >> sys.stderr,"\n\n"
    print >> sys.stderr,"Max Stride for %lx - %d bytes"%(ptr_update_pc, max_stride)

    if float(float(max_stride_region_count) / float(total_stride_count)) >= float(0.7):
        print >> sys.stderr, "%lx"%(ptr_update_pc)
        print >> sys.stderr, "This is an indirect access"
        return (True, max_stride)

    return (False, 0)

#returns (track_reg)
def pointer_analysis_with_trace_hints(track_reg, is_track_idx_reg, delinq_load_addr, BB_addr, trace_q, cfg, pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, delinq_loads_update_addr, update_trace_dict, prefetch_decisions, conf):

    BBs_in_loop = []

    update_trace_q = Queue.Queue(10)
    
    precomp_q = Queue.Queue(11)

    last_trace_pc = trace_q.popleft()


    if last_trace_pc != delinq_load_addr:
        return

    inter_delinq_loads = 0

    score = 0

    is_reg_pushed_on_stack = False

    equal_reg = None
    

    while trace_q:

        pc_in_trace = trace_q.popleft()

        if pc_in_trace == 0:
            return

        BB_addr = static_BB_cfg.discover_BB_for_address(pc_in_trace, cfg.BB_dict)

        if BB_addr == None:
            cfg = disassm.get_func_disassm(cfg.exec_file, pc_in_trace)
            BB_addr = static_BB_cfg.discover_BB_for_address(pc_in_trace, cfg.BB_dict)
            if BB_addr == None:
                return

        if not BB_addr in BBs_in_loop:
            BBs_in_loop.append(BB_addr)

        tag = None
        if pc_in_trace in cfg.ins_tags_dict:
            tag = cfg.ins_tags_dict[pc_in_trace]
            if pc_in_trace in conf.all_delinq_loads_list and prefetch_decisions:
                if prefetch_decisions[pc_in_trace].l3_mr >= 0.01:
                    inter_delinq_loads += 1
                elif prefetch_decisions[pc_in_trace].l2_mr >= 0.05:
                    inter_delinq_loads += 1
                elif prefetch_decisions[pc_in_trace].l1_mr >= 0.2:
                    inter_delinq_loads += 1

        score += 1


        if update_trace_q.full():
            print >> sys.stderr, "Too deep object nesting encountered: NestTrace @ \n"
            print >> sys.stderr, update_trace_q
            return BBs_in_loop

        #ignore writes
        if not pc_in_trace in cfg.ins_dst_regs_dict.keys():
            continue
        reg_updated_curr_pc = cfg.ins_dst_regs_dict[pc_in_trace][0]

#        if pc_in_trace in update_trace_q.queue and tag != "Move":
        if reg_updated_curr_pc == track_reg and (is_track_idx_reg or ( any(pc_in_trace in x for x in update_trace_q.queue) and tag != "Move" )):

            if not pc_in_trace in pointer_update_addr_dict:
                pointer_update_addr_dict[pc_in_trace] = 1
            else:
                pointer_update_addr_dict[pc_in_trace] += 1
              
#            record_time_to_update(delinq_load_addr, pc_in_trace, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, BBs_in_loop, delinq_loads_update_addr, prefetch_decisions, conf)

#            print >> sys.stderr, ''.join('0x%02x ' % b for b in update_trace_q.queue )

#            print >> sys.stderr, "%lx"%(pc_in_trace)

            precomp_q.put(delinq_load_addr)

            up_score = 0

            if not is_track_idx_reg:
                while any(pc_in_trace in x for x in update_trace_q.queue): #pc_in_trace in update_trace_q.queue:
                    #            while update_trace_q.queue:
                    pc_score_t = update_trace_q.get()
                    pc = pc_score_t[0]
                    up_score = pc_score_t[1]
                    precomp_q.put(pc)

            elif is_track_idx_reg:
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)
                while not update_trace_q.empty(): 
                    pc_score_t = update_trace_q.get()
                    pc = pc_score_t[0]
                    precomp_q.put(pc)

#                precomp_q.put(pc_in_trace)

#            print >> sys.stderr, ''.join('0x%02x ' % b for b in precomp_q.queue )
#            while update_trace_q.queue:
#                pc_score_t = update_trace_q.get()
#                pc = pc_score_t[0]
#                print >> sys.stderr,"%lx"%(pc)

#            print >> sys.stderr, "processed precomp queue!"

            record_update_time(delinq_load_addr, up_score, pointer_update_time_dict, inter_delinq_loads, delinq_loads_till_use)
            record_update_addr(delinq_load_addr, pc_in_trace, delinq_loads_update_addr)

#            while update_trace_q.queue:
#                loop_score = update_trace_q.get()[1]

            loop_score = score

            fwd_score = loop_score - up_score

            record_update_time(delinq_load_addr, fwd_score, time_to_update_dict, 0, delinq_loads_till_update)

            precomp_q_t = tuple(list(precomp_q.queue))

            record_update_trace(precomp_q_t, update_trace_dict)

            return BBs_in_loop


        if reg_updated_curr_pc == track_reg and not is_reg_pushed_on_stack: #the register value should not be on the stack during this

            if tag == "Read":
                reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
                track_reg = reg_read
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)
                if cfg.ins_idx_reg_dict[pc_in_trace] != 0:
                    track_reg = cfg.ins_idx_reg_dict[pc_in_trace]
                    is_track_idx_reg = True
                    #print >> sys.stderr, "Tracking index register %s from pc @ %lx"%(cfg.regs_dict[track_reg], pc_in_trace)

            # move r1, r2  -- not mem op
            elif tag == "Move":
                if pc_in_trace in cfg.ins_src_regs_dict:
                    reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
                    equal_reg = track_reg
                    track_reg = reg_read
                else:
                    cfg.ins_tags_dict[pc_in_trace] = "MoveConst"
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)
            
            #if the register being tracked is read from the stack
            elif tag == "StackR":
                print >> sys.stderr,"Register pushed on stack @ %lx"%(pc_in_trace)
                is_reg_pushed_on_stack = True #beyond this instruction the value is on the stack
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)

            # Not move but some instruction that changes track_reg and not traceable further (for now)
            # modify this case for the LEA instruction
            elif tag == "Lea":
                reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
                track_reg = reg_read
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)
                if cfg.ins_idx_reg_dict[pc_in_trace] != 0:
                    track_reg = cfg.ins_idx_reg_dict[pc_in_trace]
                    is_track_idx_reg = True
                    #print >> sys.stderr, "Tracking index register %s from pc @ %lx"%(cfg.regs_dict[track_reg], pc_in_trace)

            else:
#                return
#                reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
#                track_reg = reg_read
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)

        elif tag == "StackW":
            reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
            if track_reg == reg_read:
                is_reg_pushed_on_stack = False #beyond this the value is in **some** register
                pc_score_t = (pc_in_trace, score)
                update_trace_q.put(pc_score_t)

    # reaching this point is failure to find update instruction

#    print >> sys.stderr, "Failed to locate update point for %lx" % (delinq_load_addr)
#    print >> sys.stderr, update_trace_q

    return
    

def detect_pointer_chasing(global_pc_smptrace_hist, global_pc_stride_hist, delinq_load_addr, prefetch_decisions, cfg, conf):

    pc_mem_dis_weights_dict = {}

    pc_smptrace_hist = global_pc_smptrace_hist[delinq_load_addr]

    pointer_update_addr_dict = {}
    pointer_update_time_dict = {}
    time_to_update_dict = {}
    delinq_loads_till_update = {}
    delinq_loads_till_use = {}
    delinq_loads_update_addr = {}
    is_track_idx_reg = False

    update_trace_dict = {}

    all_BBs_in_loop = []

    NestedObjFlag = False

    track_reg = cfg.ins_base_reg_dict[delinq_load_addr]
    
    print >> sys.stderr, "Tracing update point for pc %lx"%(delinq_load_addr)

    if cfg.ins_idx_reg_dict[delinq_load_addr] != 0:
        track_reg = cfg.ins_idx_reg_dict[delinq_load_addr]
        is_track_idx_reg = True
#        print >> sys.stderr, "Tracking index register %s for delinq load @ %lx"%(cfg.regs_dict[track_reg], delinq_load_addr)

    BB_addr = static_BB_cfg.discover_BB_for_address(delinq_load_addr, cfg.BB_dict)

    for time in pc_smptrace_hist.keys():
        trace = pc_smptrace_hist[time]
            
        trace_q = deque(trace)

        BBs_inspected = []

        status = pointer_analysis_with_trace_hints(track_reg, is_track_idx_reg, delinq_load_addr, BB_addr, trace_q, cfg, pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, delinq_loads_update_addr, update_trace_dict, prefetch_decisions, conf)
        
        BBs_in_loop = status
            

        if BBs_in_loop:
            all_BBs_in_loop += filter(lambda x: x not in all_BBs_in_loop, BBs_in_loop)
        

    freq_update_trace_t = dominant_update_trace(update_trace_dict)
    
    is_ind = False
    stride = 0
    


    if freq_update_trace_t:
        print >> sys.stderr, "Traceable delinq load: %lx"%(delinq_load_addr)
        (is_ind, stride) = is_indirect_addr(freq_update_trace_t, global_pc_stride_hist, cfg)

    return (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop, is_ind, stride)
