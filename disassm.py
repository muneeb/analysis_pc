import subprocess
import static_BB_cfg
import re

class CFG_Info:

    ins_src_regs_dict = {}
    ins_dst_regs_dict = {}
    ins_tags_dict = {}
    branch_dict = {}
    routine_addr_range = []
    ins_base_reg_dict = {}
    ins_mem_dis_dict = {}
    ins_idx_reg_dict = {}
    ins_mem_scale_dict = {}
    BB_dict = {}
    vol_regs_dict = {17:"rdx", 18:"rcx", 19:"rax", 20:"r8", 21:"r9", 22:"r10", 23:"r11"}
    regs_dict = {12:"rdi", 13:"rsi", 14:"rbp", 15:"rsp", 16:"rbx", 17:"rdx", 18:"rcx", 19:"rax", 20:"r8", 21:"r9", 22:"r10", 23:"r11", 24:"r12", 25:"r13", 26:"r14", 27:"r15"}
    exec_file = None

    def __init__(self, ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict, BB_dict, exec_file):
        self.ins_src_regs_dict.update(ins_src_regs_dict)
        self.ins_dst_regs_dict.update(ins_dst_regs_dict)
        self.ins_tags_dict.update(ins_tags_dict)
        self.branch_dict.update(branch_dict)
        self.routine_addr_range = routine_addr_range
        self.ins_base_reg_dict.update(ins_base_reg_dict)
        self.ins_mem_dis_dict.update(ins_mem_dis_dict)
        self.ins_idx_reg_dict.update(ins_idx_reg_dict)
        self.ins_mem_scale_dict.update(ins_mem_scale_dict)
        self.BB_dict.update(BB_dict)
        self.exec_file = exec_file
#        self.vol_regs_dict = {17:"rdx", 18:"rcx", 19:"rax", 20:"r8", 21:"r9", 22:"r10", 23:"r11"}
#        self.regs_dict = {12:"rdi", 13:"rsi", 16:"rbx", 17:"rdx", 18:"rcx", 19:"rax", 20:"r8", 21:"r9", 22:"r10", 23:"r11", 24:"r12", 25:"r13", 26:"r14", 27:"r15"}

def parse_routine_info(routine):

    re_hex_address = re.compile("0[xX][0-9a-fA-F]+")

    ins_src_regs_dict = {}
    ins_dst_regs_dict = {}
    ins_tags_dict = {}
    branch_dict = {}
    routine_addr_range = []

    # information maps for Memory operations
    ins_base_reg_dict = {}
    ins_mem_dis_dict = {}
    ins_idx_reg_dict = {}
    ins_mem_scale_dict = {}

    tag_list = ['IndirectBranch', 'IndirectCondBranch', 'Branch', 'CondBranch', 'Call', 'Ret', 'StackR', 'StackW', 'Read', 'Write', 'Move', 'Nop', 'Lea']

    line_tokens = routine.split('\n')

    target_address = 0
    tag_br_target_for_this_pc = 0

    for line in line_tokens:

        tokens = line.split()

        if(len(tokens) > 0 and tokens[0] == "instr:"):
            instr_addr = int(tokens[1], 16)
            routine_addr_range.append(instr_addr)
            target_address = re_hex_address.findall(line)

            if tag_br_target_for_this_pc != 0:
                branch_dict[tag_br_target_for_this_pc].append(instr_addr)
                tag_br_target_for_this_pc = 0

            instr = tokens[2]

            print line

        elif(len(tokens) > 0):
            
            src_regs = []
            dst_regs = []
            
            for reg_info in tokens:
                
                if reg_info.find("R:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    reg_id = int(reg_info_tokens[1], 16)
                    if not reg_id in src_regs:
                        src_regs.append(reg_id)

                elif reg_info.find("W:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    reg_id = int(reg_info_tokens[1], 16)
                    if not reg_id in dst_regs:
                        dst_regs.append(reg_id)

                elif reg_info.find("MemBaseReg:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    base_reg_id = int(reg_info_tokens[1], 16)
                    ins_base_reg_dict[instr_addr] = base_reg_id

                elif reg_info.find("MemDis:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    mem_dis = int(reg_info_tokens[1], 16)
                    ins_mem_dis_dict[instr_addr] = mem_dis

                elif reg_info.find("MemIdxReg:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    idx_reg_id = int(reg_info_tokens[1], 16)
                    ins_idx_reg_dict[instr_addr] = idx_reg_id

                elif reg_info.find("MemScale:") != -1:
                    reg_info_tokens = reg_info.split(":")
                    mem_scale = int(reg_info_tokens[1], 16)
                    ins_mem_scale_dict[instr_addr] = mem_scale

            ins_src_regs_dict[instr_addr] =  src_regs

            if len(dst_regs) > 0:
                ins_dst_regs_dict[instr_addr] =  dst_regs

            ins_tag = tokens.pop()

            if( ins_tag in tag_list ):
                ins_tags_dict[instr_addr] = ins_tag

            if( ins_tag == 'Branch'):
                br_target_pc = int(target_address[0], 16)
                branch_dict[instr_addr] = [br_target_pc]
            elif( ins_tag == 'CondBranch'):
                br_target_pc = int(target_address[0], 16)
                tag_br_target_for_this_pc = instr_addr #add information for fall through in next iteration when address for next instruction is discovered
                branch_dict[instr_addr] = [br_target_pc]
            elif( ins_tag == 'IndirectBranch' or  ins_tag == 'Ret'):
                br_target_pc = 0   # target instruction is not known
                branch_dict[instr_addr] = [br_target_pc]
            elif( ins_tag == 'IndirectCondBranch'):
                br_target_pc = 0   # target instruction is not known
                tag_br_target_for_this_pc = instr_addr #add information for fall through in next iteration when address for next instruction is discovered
                branch_dict[instr_addr] = [br_target_pc]

#            print line


    return [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict]

def get_func_disassm(exec_file, instr_addr):

    routine = subprocess.Popen(["/home/muneeb/git/disasm/obj-intel64/get_routine", "-a", str(instr_addr), "-i", exec_file], stdout=subprocess.PIPE).communicate()[0]

    [ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict] = parse_routine_info(routine)

    BB_dict = static_BB_cfg.build_static_routine_CFG(ins_tags_dict, branch_dict, routine_addr_range)

    cfg = CFG_Info(ins_src_regs_dict, ins_dst_regs_dict, ins_tags_dict, branch_dict, routine_addr_range, ins_base_reg_dict, ins_mem_dis_dict, ins_idx_reg_dict, ins_mem_scale_dict, BB_dict, exec_file)

    return cfg
