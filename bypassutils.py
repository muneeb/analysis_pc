import sys
import pyusf
import numpy

def print_and_exit(s):
    print >> sys.stderr, s
    sys.exit(1)

def add_sample(rdist_hist, rdist):
    if rdist_hist.has_key(rdist):
        rdist_hist[rdist] += 1
    else:
        rdist_hist[rdist] = 1

def addto_pc_rdist_hist(pc_rdist_hist, pc, rdist):

#   pc_rdist_hist -> { pc: { rdist: count } }

    if pc_rdist_hist.has_key(pc):
        pc_rdist_hist[pc][rdist] = pc_rdist_hist[pc].get(rdist, 0) + 1

    else:
        pc_rdist_hist[pc] = {}
        pc_rdist_hist[pc][rdist] = 1

def addto_pc_fwd_rdist_hist(pc_fwd_rdist_hist, pc, rdist):

#   pc_fwd_rdist_hist -> { pc: { rdist: count } }

    if pc_fwd_rdist_hist.has_key(pc):
        pc_fwd_rdist_hist[pc][rdist] = pc_fwd_rdist_hist[pc].get(rdist, 0) + 1

    else:
        pc_fwd_rdist_hist[pc] = {}
        pc_fwd_rdist_hist[pc][rdist] = 1

def addto_pc_stride_hist(pc_stride_hist, pc, stride):

#   pc_stride_hist -> { pc: { stride: count } }

    if pc_stride_hist.has_key(pc):
        pc_stride_hist[pc][stride] = pc_stride_hist[pc].get(stride, 0) + 1

    else:
        pc_stride_hist[pc] = {}
        pc_stride_hist[pc][stride] = 1

def addto_pc_smptrace_hist(pc_smptrace_hist, pc, time, smptrace):
    
# pc_smptrace_hist -> { pc: { time: [smptrace] } }

    if pc_smptrace_hist.has_key(pc):
        pc_smptrace_hist[pc][time] = smptrace
        
    else:
        pc_smptrace_hist[pc] = {}
        pc_smptrace_hist[pc][time] = smptrace

def addto_pc_freq_hist(pc_freq_hist, pc):

#   pc_freq_hist -> { pc: count }

    pc_freq_hist[pc] = pc_freq_hist.get(pc, 0) + 1


def addto_pc_time_hist(pc_time_hist, pc, time):

#   pc_time_hist -> { pc: { pc_repeat_time: count } }

    if pc_time_hist.has_key(pc):
        pc_time_hist[pc][time] = pc_time_hist[pc].get(time, 0) + 1

    else:
        pc_time_hist[pc] = {}
        pc_time_hist[pc][time] = 1

def addto_pc_to_pc_corr_hist(pc_corr_hist, start_pc, end_pc):

#   pc_corr_hist -> { start_pc: { end_pc: count } }

    if pc_corr_hist.has_key(start_pc):
        pc_corr_hist[start_pc][end_pc] = pc_corr_hist[start_pc].get(end_pc, 0) + 1

    else:
        pc_corr_hist[start_pc] = {}
        pc_corr_hist[start_pc][end_pc] = 1

def addto_pc_line_hist(pc_line_hist, pc, line):

#   pc_line_hist -> { pc: { line_addr: count } }

    if pc_line_hist.has_key(pc):
        pc_line_hist[pc][line] = pc_line_hist[pc].get(line, 0) + 1

    else:
        pc_line_hist[pc] = {}
        pc_line_hist[pc][line] = 1

def addto_line_rdist_hist(line_rdist_hist, line, rdist):

#   line_rdist_hist -> { line_addr: { rdist: count } }

    if line_rdist_hist.has_key(line):
        line_rdist_hist[line][rdist] = line_rdist_hist[line].get(line, 0) + 1

    else:
        line_rdist_hist[line] = {}
        line_rdist_hist[line][rdist] = 1


def filter_true(begin, end, rdist):
    return True

def usf_read_events(usf_file, line_size, filter=filter_true):
    rdist_burst_hist = []

    assert(not (usf_file.header.flags & pyusf.USF_FLAG_TRACE))
    burst_mode = usf_file.header.flags & pyusf.USF_FLAG_BURST
    if not burst_mode:
        rdist_burst_hist.append(({}, {}, {}, {}))

    for event in usf_file:
        if isinstance(event, pyusf.Burst):
            if burst_mode:
                rdist_burst_hist.append(({}, {}, {}, {}))
            else:
                print >> sys.stderr, "Warning: Ignored burst event in " \
                    "non-burst file."
            continue

        assert(isinstance(event, pyusf.Sample) or \
                   isinstance(event, pyusf.Stride) or \
                   isinstance(event, pyusf.Smptrace) or \
                   isinstance(event, pyusf.Dangling))
        
        if not isinstance(event, pyusf.Smptrace):
            if (1 << event.line_size) != line_size:
                continue

        (pc_rdist_hist, pc_freq_hist, pc_corr_hist, pc_fwd_rdist_hist) = rdist_burst_hist[-1]

        if isinstance(event, pyusf.Sample):
#            assert(event.begin.time < event.end.time)
            if not event.begin.time < event.end.time:
                print >> sys.stderr, "error: event.begin.time NOT < event.end.time"
                continue
            rdist = event.end.time - event.begin.time - 1
            addto_pc_rdist_hist(pc_rdist_hist, event.end.pc, rdist)
            addto_pc_fwd_rdist_hist(pc_fwd_rdist_hist, event.begin.pc, rdist)
            addto_pc_freq_hist(pc_freq_hist, event.begin.pc)
            addto_pc_to_pc_corr_hist(pc_corr_hist, event.begin.pc, event.end.pc)
        elif isinstance(event, pyusf.Dangling):
            rdist = sys.maxint
            addto_pc_rdist_hist(pc_rdist_hist, event.begin.pc, rdist)
            addto_pc_fwd_rdist_hist(pc_fwd_rdist_hist, event.begin.pc, rdist)
            addto_pc_freq_hist(pc_freq_hist, event.begin.pc)


    return rdist_burst_hist

def parse_usf(file_name, line_size, filter=filter_true):
    try:
        usf_file = pyusf.Usf()
        usf_file.open(file_name)
    except IOError, e:
        print_and_exit(str(e))

    if usf_file.header.flags & pyusf.USF_FLAG_TRACE:
        print_and_exit("XXX")

    if not usf_file.header.line_sizes & line_size:
        print_and_exit("Line size (%i) not available in USF file." % line_size)

    rdist_burst_hist = usf_read_events(usf_file,
                                       line_size=line_size,
                                       filter=filter)

    usf_file.close()
    return rdist_burst_hist
