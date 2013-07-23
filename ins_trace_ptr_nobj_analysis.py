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

#returns (track_reg)
def pointer_analysis_with_trace_hints(track_reg, delinq_load_addr, BB_addr, trace_q, cfg, pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, delinq_loads_update_addr, prefetch_decisions, conf):

    BBs_in_loop = []

    update_trace_q = Queue.Queue(10)
    
    ptr_update_q = Queue.Queue(3)
    
    nested_obj_q = Queue.Queue(5)

    last_trace_pc = trace_q.popleft()

    if last_trace_pc != delinq_load_addr:
        return

    inter_delinq_loads = 0

    score = 0

    is_reg_pushed_on_stack = False


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

        if pc_in_trace in update_trace_q.queue and tag != "Move":

            if not pc_in_trace in pointer_update_addr_dict:
                pointer_update_addr_dict[pc_in_trace] = 1
            else:
                pointer_update_addr_dict[pc_in_trace] += 1
                
            record_update_time(delinq_load_addr, score, pointer_update_time_dict, inter_delinq_loads, delinq_loads_till_use)
            record_update_addr(delinq_load_addr, pc_in_trace, delinq_loads_update_addr)
            record_time_to_update(delinq_load_addr, pc_in_trace, trace_q, cfg, time_to_update_dict, delinq_loads_till_update, BBs_in_loop, delinq_loads_update_addr, prefetch_decisions, conf)

            print >> sys.stderr, "pointer update at %lx" % (pc_in_trace)

            while update_trace_q.queue:
                print >> sys.stderr, "%lx" % (update_trace_q.get())
            
            print >> sys.stderr, ""
            
            return BBs_in_loop


        if not pc_in_trace in cfg.ins_dst_regs_dict.keys():
            continue

        reg_updated_curr_pc = cfg.ins_dst_regs_dict[pc_in_trace][0]

        if reg_updated_curr_pc == track_reg and not is_reg_pushed_on_stack: #the register value should not be on the stack during this

            if tag == "Read":
                reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
                track_reg = reg_read
                update_trace_q.put(pc_in_trace)
                

                # move r1, r2  -- not mem op
            elif tag == "Move":
                reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
                track_reg = reg_read
                update_trace_q.put(pc_in_trace)
            
                #if the register being tracked is read from the stack
            elif tag == "StackR":
                is_reg_pushed_on_stack = True #beyond this instruction the value is on the stack

            # Not move but some instruction that changes track_reg and not traceable further (for now)
            # modify this case for the LEA instruction
            else:
                reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
                track_reg = reg_read
                update_trace_q.put(pc_in_trace)

        elif tag == "StackW":
            reg_read = cfg.ins_src_regs_dict[pc_in_trace][0]
            if track_reg == reg_read:
                is_reg_pushed_on_stack = False #beyond this the value is in **some** register
                

    # reaching this point is failure to find update instruction

    print >> sys.stderr, "Failed to locate update point for %lx" % (delinq_load_addr)
    print >> sys.stderr, update_trace_q

    return
    

def detect_pointer_chasing(global_pc_smptrace_hist, delinq_load_addr, prefetch_decisions, cfg, conf):

    pc_mem_dis_weights_dict = {}

    pc_smptrace_hist = global_pc_smptrace_hist[delinq_load_addr]

    pointer_update_addr_dict = {}
    pointer_update_time_dict = {}
    time_to_update_dict = {}
    delinq_loads_till_update = {}
    delinq_loads_till_use = {}
    delinq_loads_update_addr = {}

    all_BBs_in_loop = []

    NestedObjFlag = False

    reg_read_orig = cfg.ins_base_reg_dict[delinq_load_addr]

    BB_addr = static_BB_cfg.discover_BB_for_address(delinq_load_addr, cfg.BB_dict)

    for time in pc_smptrace_hist.keys():
        trace = pc_smptrace_hist[time]
            
        trace_q = deque(trace)

        BBs_inspected = []

        status = pointer_analysis_with_trace_hints(reg_read_orig, delinq_load_addr, BB_addr, trace_q, cfg, pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, delinq_loads_update_addr, prefetch_decisions, conf)
        
        BBs_in_loop = status
            

        if BBs_in_loop:
            all_BBs_in_loop += filter(lambda x: x not in all_BBs_in_loop, BBs_in_loop)
        

    return (pointer_update_addr_dict, pointer_update_time_dict, time_to_update_dict, delinq_loads_till_update, delinq_loads_till_use, all_BBs_in_loop)
