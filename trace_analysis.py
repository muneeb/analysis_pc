#!/usr/bin/python

import string
import sys
import re
import operator
import os
import pyusf
import utils

import static_BB_cfg

from collections import deque

def add_trace_to_global_pc_smptrace_hist(global_pc_smptrace_hist, pc_smptrace_dict):

    for pc in pc_smptrace_dict.keys():
        for time in pc_smptrace_dict[pc].keys():
            smptrace = pc_smptrace_dict[pc][time]
            utils.addto_pc_smptrace_hist(global_pc_smptrace_hist, pc, time, smptrace)

    return


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


def record_time_to_update(delinq_load_addr, update_addr, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, conf):

    if not delinq_load_addr in trace_q:
        return

    fwd_score = 0
    fwd_delinq_loads = 0

    BB_addr = static_BB_cfg.discover_BB_for_address(update_addr, cfg.BB_dict)
    
    reversed_BB_addr_range = sorted(cfg.BB_dict[BB_addr], reverse=True)

    reversed_BB_addr_range = filter(lambda x: x < update_addr, reversed_BB_addr_range)
    
    pc_in_trace =  trace_q.popleft()

    pc_in_BB = None

    while trace_q:

        for pc_in_BB in reversed_BB_addr_range:

            if pc_in_BB == update_addr:
                break

            if pc_in_BB in cfg.ins_tags_dict:
                if pc_in_BB in conf.all_delinq_loads_list:
                    fwd_delinq_loads += 1
                    
            fwd_score += 1
        
        if pc_in_BB == update_addr:
            break
            
        while pc_in_trace in reversed_BB_addr_range:
            if trace_q:
                pc_in_trace = trace_q.popleft()
            else:
                return

        BB_addr = static_BB_cfg.discover_BB_for_address(pc_in_trace, cfg.BB_dict)
        
        if BB_addr == None:
            return

        reversed_BB_addr_range = sorted(cfg.BB_dict[BB_addr], reverse=True)
            

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


#returns (track_reg)
def pointer_analysis_with_trace_hints(track_reg, delinq_load_addr, BB_addr, trace_q, cfg, pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, conf):

#    print BB_addr, BBs_inspected, pointer_update_addr_list

    BBs_inspected = []

    pc_in_trace = last_trace_pc = trace_q.popleft()

#    if last_trace_pc != delinq_load_addr:
#        return

    inter_delinq_loads = 0

    reversed_BB_addr_range = sorted(cfg.BB_dict[BB_addr], reverse=True)
    
    # x <= last_trace_pc means include self update analysis also. We want to avoid that
    reversed_BB_addr_range = filter(lambda x: x < last_trace_pc, reversed_BB_addr_range)

    score = 0
    
    while True:
        
        BBs_inspected.append(BB_addr)

        for pc_in_BB in reversed_BB_addr_range:
            
            tag = None
            if pc_in_BB in cfg.ins_tags_dict:
                if pc_in_BB in conf.all_delinq_loads_list:
                    inter_delinq_loads += 1
                    
            score += 1

            if not pc_in_BB in cfg.ins_dst_regs_dict.keys():
                continue

            reg_updated_curr_pc = cfg.ins_dst_regs_dict[pc_in_BB][0]


            if reg_updated_curr_pc == track_reg:

                if tag == "Read":
                    if not pc_in_BB in pointer_update_addr_dict:
                        pointer_update_addr_dict[pc_in_BB] = 1
                    else:
                        pointer_update_addr_dict[pc_in_BB] += 1
                    track_reg = None
                    #should not include the pointer update instruction, its latency should not be counted
                    score -= 1
                    record_update_time(delinq_load_addr, score, pointer_update_time_dict, inter_delinq_loads, delinq_loads_till_use)
                    record_time_to_update(delinq_load_addr, pc_in_BB, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, conf)
                    return
#                        return track_reg
                
                # move r1, r2  -- not mem op
                elif tag == "Move":
                    reg_read = cfg.ins_src_regs_dict[pc_in_BB][0]
                    track_reg = reg_read
#                    print ">> %lu <<"%(pc_in_BB)
                
                # Not move but some instruction that changes track_reg and not traceable further
                else:
                    if not pc_in_BB in pointer_update_addr_dict:
                        pointer_update_addr_dict[pc_in_BB] = 1
                    else:
                        pointer_update_addr_dict[pc_in_BB] += 1
                    track_reg = None
                    score -= 1
                    record_update_time(delinq_load_addr, score, pointer_update_time_dict, inter_delinq_loads, delinq_loads_till_use)
                    record_time_to_update(delinq_load_addr, pc_in_BB, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, conf)
                    return

        while pc_in_trace in reversed_BB_addr_range:
            if trace_q:
                pc_in_trace = trace_q.popleft()
            else:
                return


        if pc_in_trace == 0 or pc_in_trace in reversed_BB_addr_range:
            return

        BB_addr = static_BB_cfg.discover_BB_for_address(pc_in_trace, cfg.BB_dict)

        if BB_addr == None:
            return

        reversed_BB_addr_range = sorted(cfg.BB_dict[BB_addr], reverse=True)

        

    record_update_time(delinq_load_addr, score, pointer_update_time_dict, inter_delinq_loads, delinq_loads_till_use)
    record_time_to_update(delinq_load_addr, pc_in_BB, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, conf)

    return track_reg
    

def detect_pointer_chasing(global_pc_smptrace_hist, delinq_load_addr, cfg, conf):

    pc_mem_dis_weights_dict = {}

    pc_smptrace_hist = global_pc_smptrace_hist[delinq_load_addr]

    pointer_update_addr_dict = {}
    pointer_update_time_dict = {}
    time_to_update_dict = {}
    delinq_loads_till_update = {}
    delinq_loads_till_use = {}

    reg_read_orig = cfg.ins_base_reg_dict[delinq_load_addr]

    for time in pc_smptrace_hist.keys():
        trace = pc_smptrace_hist[time]
            
        trace_q = deque(trace)
        BB_addr = static_BB_cfg.discover_BB_for_address(delinq_load_addr, cfg.BB_dict)
        
        BBs_inspected = []

        pointer_analysis_with_trace_hints(reg_read_orig, delinq_load_addr, BB_addr, trace_q, cfg, pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, conf)


    print len(pc_smptrace_hist.keys())
    print pointer_update_addr_dict

    return (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use)
