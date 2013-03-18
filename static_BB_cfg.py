import sys


def build_static_routine_CFG(ins_tags_dict, branch_dict, routine_addr_range):

    BB_dict = {}
    BB = []

    branch_tags = ['IndirectBranch', 'IndirectCondBranch', 'Branch', 'CondBranch', 'Ret']


    for pc in routine_addr_range:
        BB.append(pc)
        if pc in ins_tags_dict.keys():
            if ins_tags_dict[pc] in branch_tags:
                BB_start_pc = BB[0]
                BB_dict[BB_start_pc] = BB
                BB = []

    br_target_BBs = []

    for branches in branch_dict.keys():
        br_target_list = branch_dict[branches]
        for br_target in br_target_list:
            if not br_target in BB_dict.keys():
                if not br_target in br_target_BBs:
                    br_target_BBs.append(br_target)


    while len(br_target_BBs) > 0:
        BB = []
        br_target = br_target_BBs.pop()
        
        i = routine_addr_range.index(br_target)

        for pc in routine_addr_range[i:len(routine_addr_range)]:

            BB.append(pc)

            if pc in ins_tags_dict.keys():
                if ins_tags_dict[pc] in branch_tags:
                    BB_start_pc = BB[0]
                    BB_dict[BB_start_pc] = BB
                    BB = []

    return BB_dict

def discover_BB_for_address(instr_addr, routine_BB_dict):

    BBs_list = []

    for BB_addr in routine_BB_dict.keys():
        BB_addr_range = routine_BB_dict.get(BB_addr)
        if instr_addr in BB_addr_range:
            BB_addr_len_tup = (BB_addr, len(BB_addr_range))
            BBs_list.append(BB_addr_len_tup)

    if not BBs_list:
#        print >> sys.stderr, "ERROR: NO BB found for %lx" % (instr_addr)
        return

    (BB_addr, BB_len) = max(BBs_list, key=lambda x: x[1])

    #return the longest BB containing the instruction
    return BB_addr

def is_instr_in_this_BB(instr_addr, BB_addr_to_check, routine_BB_dict):

    BB_addr_range = routine_BB_dict.get(BB_addr_to_check)
    if instr_addr in BB_addr_range:
        return True

    return False

def get_entry_point_branches(BB_addr, routine_BB_dict, branch_dict):

    entry_point_branches = []

    for branch in branch_dict.keys():
        
        # if the basic block address is in the branch targets
        if BB_addr in branch_dict[branch]:
            entry_point_branches.append(branch)

    return entry_point_branches

def get_next_BBs(instr_addr, routine_BB_dict, branch_dict):

    BB_addr = discover_BB_for_address(instr_addr, routine_BB_dict)

    BB_addr_range = routine_BB_dict.get(BB_addr)
    
    BB_last_branch = max(BB_addr_range)

    next_BBs_list = branch_dict[BB_last_branch]

    return next_BBs_list 

def check_usable_regs_from_next_BBs(instr_addr, cfg):

    next_BBs_list = get_next_BBs(instr_addr, cfg.BB_dict, cfg.branch_dict)

    #registers that are written but not read before that
    usable_regs = []
    unusable_regs = []

    for BB_addr in next_BBs_list:
        
        if not BB_addr in cfg.BB_dict:
            return []

        reversed_BB_addr_range = sorted(cfg.BB_dict[BB_addr], reverse=True)

        curr_BB_usable_regs = []

        for instr_addr in reversed_BB_addr_range:
            if instr_addr in cfg.ins_dst_regs_dict:
                reg_written = cfg.ins_dst_regs_dict[instr_addr][0]
                if not reg_written in curr_BB_usable_regs:
                    curr_BB_usable_regs.append(reg_written)
                
                for reg in curr_BB_usable_regs:
                    if reg in cfg.ins_src_regs_dict[instr_addr]:
                        curr_BB_usable_regs.remove(reg)
                        if reg not in unusable_regs:
                            unusable_regs.append(reg)

        usable_regs += filter(lambda x: x not in usable_regs, curr_BB_usable_regs)


    BB_addr = discover_BB_for_address(instr_addr, cfg.BB_dict)
        

    reversed_BB_addr_range = sorted(cfg.BB_dict[BB_addr], reverse=True)
    reversed_BB_addr_range = filter(lambda x: x >= instr_addr, reversed_BB_addr_range)

    curr_BB_usable_regs = []

    for instr_addr in reversed_BB_addr_range:
        if instr_addr in cfg.ins_dst_regs_dict:
            reg_written = cfg.ins_dst_regs_dict[instr_addr][0]
            if not reg_written in curr_BB_usable_regs:
               curr_BB_usable_regs.append(reg_written)
            
            for reg in curr_BB_usable_regs:
                if reg in cfg.ins_src_regs_dict[instr_addr]:
                    curr_BB_usable_regs.remove(reg)
                    if reg not in unusable_regs:
                        unusable_regs.append(reg)
        
    usable_regs += filter(lambda x: x not in usable_regs, curr_BB_usable_regs)

    usable_regs = filter(lambda x: x not in unusable_regs, usable_regs)

    print usable_regs
    print unusable_regs

    return usable_regs


def check_dependencies_in_reverse(delinq_load_addr, BB_addr, ins_src_regs_dict, ins_dst_regs_dict, ins_base_reg_dict, routine_BB_dict, ins_tags_dict, branch_dict, track_reg=None):

    pointer_update_dep_list = []

    delinq_load_base_reg_id = ins_base_reg_dict[delinq_load_addr]
    
    reversed_BB_addr_range = sorted(routine_BB_dict[BB_addr], reverse=True)

    if track_reg == None:
        track_reg = delinq_load_base_reg_id

    for instr_addr in reversed_BB_addr_range:
        
        if instr_addr in ins_dst_regs_dict and len(ins_dst_regs_dict[instr_addr]) > 0:
            
            reg_updated = ins_dst_regs_dict[instr_addr][0] 
            reg_read = ins_src_regs_dict[instr_addr][0]
            
            tag = None
            if instr_addr in ins_tags_dict.keys():
                tag = ins_tags_dict[instr_addr]

            if reg_updated == track_reg:
                
                # p = p->next
                if tag == "Read":
                    pointer_update_addr = instr_addr
                    track_reg = None
                    return pointer_update_addr
                
                # move r1, r2  -- not mem op
                elif tag != "Read":
#                    pointer_update_dep_list.append(instr_addr)
                    track_reg = reg_read
            
#                else:
#                    pointer_update_dep_list.append(instr_addr)
#                    track_reg = reg_read

    
    if track_reg != None:
        entry_point_branches = get_entry_point_branches(BB_addr, routine_BB_dict, branch_dict)

        for entry_point_branch in entry_point_branches:
            preceding_BB_addr = discover_BB_for_address(entry_point_branch, routine_BB_dict)

            if preceding_BB_addr == None:
                continue

            pointer_update_addr = check_dependencies_in_reverse(delinq_load_addr, preceding_BB_addr, ins_src_regs_dict, ins_dst_regs_dict, ins_base_reg_dict, routine_BB_dict, ins_tags_dict, branch_dict, track_reg)
            pointer_update_dep_list.append(pointer_update_addr)

    return pointer_update_dep_list

def discover_self_update(delinq_load_addr, ins_dst_regs_dict, ins_base_reg_dict):
    
    if not delinq_load_addr in ins_dst_regs_dict.keys():
        return False

    reg_updated = ins_dst_regs_dict[delinq_load_addr][0]
    delinq_load_base_reg_id = ins_base_reg_dict[delinq_load_addr]

    if reg_updated == delinq_load_base_reg_id:
        return True

    return False

def is_mem_loc_accessed_in_BB(base_reg_id, mem_dis, delinq_load_addr, cfg):

    BB_addr = discover_BB_for_address(delinq_load_addr, cfg.BB_dict)

    BB_addr_range = sorted(cfg.BB_dict[BB_addr])

    for pc_in_BB in BB_addr_range:
        if not pc_in_BB in cfg.ins_tags_dict:
            continue

        tag = cfg.ins_tags_dict[pc_in_BB]

        if tag == "Read" or tag == "Write":
            if cfg.ins_base_reg_dict[pc_in_BB] == base_reg_id and cfg.ins_mem_dis_dict[pc_in_BB] == mem_dis:
                return pc_in_BB

    return None
    

def discover_pointer_chasing_static(cfg, delinq_load_addr):
    
    print delinq_load_addr

    pointer_update_ins_list = []

    if delinq_load_addr in cfg.ins_tags_dict.keys():
        ins_tag = cfg.ins_tags_dict.get(delinq_load_addr)

        if ins_tag == "Read":
            None
    
    if not delinq_load_addr in cfg.ins_base_reg_dict.keys():
        return

    if discover_self_update(delinq_load_addr, cfg.ins_dst_regs_dict, cfg.ins_base_reg_dict):
        pointer_update_ins_list.append(delinq_load_addr)
        return pointer_update_ins_list

    BB_addr = discover_BB_for_address(delinq_load_addr, cfg.BB_dict)

    entry_point_branches = get_entry_point_branches(BB_addr, cfg.BB_dict, cfg.branch_dict)

    if len(entry_point_branches) == 0:
        pointer_update_dep_list = []

    for entry_point_branch in entry_point_branches:
        preceding_BB_addr = discover_BB_for_address(entry_point_branch, cfg.BB_dict)

        if preceding_BB_addr == None:
            continue

        pointer_update_dep_list = check_dependencies_in_reverse(delinq_load_addr, preceding_BB_addr, cfg.ins_src_regs_dict, cfg.ins_dst_regs_dict, cfg.ins_base_reg_dict, cfg.BB_dict, cfg.ins_tags_dict, cfg.branch_dict)

        if len(pointer_update_dep_list) > 0:
            print "dep list"
            print pointer_update_dep_list
        else:
            pointer_update_dep_list = []

    return pointer_update_dep_list
