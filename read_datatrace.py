import sys
import pyusf
import numpy

def print_and_exit(s):
    print >> sys.stderr, s
    sys.exit(1)

def addto_smp_datatrace_hist(smp_datatrace_hist, time, smp_datatrace):
    
# smp_datatrace_hist -> { time: { page_addr: [ (addr, pc),... ] } }
    
    smp_datatrace_hist[time] = {}
    
    for pc, addr in zip(smp_datatrace[::2], smp_datatrace[1::2]):
        page_addr = addr >> 12;
        
        if pc == 0:
            return
        
        tup = (addr, pc)
        if page_addr in smp_datatrace_hist[time].keys():
            smp_datatrace_hist[time][page_addr].append(tup)
        else:
            smp_datatrace_hist[time][page_addr] = [tup]
    

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


def filter_true(begin, end, rdist):
    return True

def usf_read_events(usf_file, line_size, filter=filter_true):
    burst_hist = []

    assert(not (usf_file.header.flags & pyusf.USF_FLAG_TRACE))
    burst_mode = usf_file.header.flags & pyusf.USF_FLAG_BURST
    if not burst_mode:
        burst_hist.append(({}, {}, {}))

    for event in usf_file:
        if isinstance(event, pyusf.Burst):
            if burst_mode:
                burst_hist.append(({}, {}, {}))
            else:
                print >> sys.stderr, "Warning: Ignored burst event in " \
                    "non-burst file."
            continue

        assert(isinstance(event, pyusf.Sample) or \
                   isinstance(event, pyusf.Stride) or \
                   isinstance(event, pyusf.Smptrace) or \
                   isinstance(event, pyusf.Smpdatatrace) or \
                   isinstance(event, pyusf.Dangling))
        
        if not (isinstance(event, pyusf.Smptrace) or isinstance(event, pyusf.Smpdatatrace)):
            if (1 << event.line_size) != line_size:
                continue

        (pc_freq_hist, pc_time_hist, smp_datatrace_hist) = burst_hist[-1]

        if isinstance(event, pyusf.Smpdatatrace):
            smp_datatrace_array = numpy.ndarray( (pyusf.SMP_DATA_TRACE_LEN,), dtype= numpy.uint64, buffer=event.data_trace)
            smp_datatrace = smp_datatrace_array.tolist()
            repeat_time = event.begin.time
            addto_smp_datatrace_hist(smp_datatrace_hist, event.begin.time, smp_datatrace)
#            addto_pc_freq_hist(pc_freq_hist, event.begin.pc)
#            addto_pc_time_hist(pc_time_hist, event.begin.pc, repeat_time)


    return burst_hist

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
