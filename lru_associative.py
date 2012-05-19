'''
Created on Nov 11, 2009

@author: dbs
'''
import missratio
import lrumodel

'''
What is the smallest amount I can implement first?
'''

'''
Open the sampled trace as sampled_trace
Open the full trace as full_trace

Create an array of sampled_reuse_distance_histograms
Create an array of sampled_set_access_histograms
Create an array of full_reuse_distance_histograms
Create an array of full_set_access_histograms

For each burst in the sampled_trace
    Create a burst_sampled_reuse_distance_histogram for each set
    Create a burst_sampled_set_access_histogram with entries for each set
    Create a burst_full_reuse_distance_histogram for each set
    Create a burst_full_set_access_histogram with entries for each set
    For each target_sample in the burst
        // Do the sampled updates
        put the target_sample reuse distance into the burst_sampled_reuse_distance_histogram for the set
        increment the bin for the set in the burst_sampled_set_access_histogram
        // Do the full updates
        increment the bin for the set in the burst_full_set_access_histogram
        Go over the samples in the full_trace between the target_sample's start and end
            Count the actual number of accesses to the target_sample's way
            Update the burst_full_set_access_histogram for the appropriate set ofr the sample
        Put the actual number of set accesses into the burst_full_reuse_distance_histogram for the set
    

        
When we are done we have:
    sampled_reuse_distance_histograms[] per burst
        burst_sampled_reuse_distance_histogram[] one histogram per set 
            each per-set histogram contains the distribution of reuse distances to
            that set as measured from the raw samples. That is, the reuse distances
            here include samples to other sets and need to be scaled.
            
    sampled_set_access_histograms[] per burst
        burst_sampled_set_access_histogram[]
            each bin contains the number of accesses to that set as counted from the
            sampled accessess.
            
    full_reuse_distance_histograms[] per burst
        burst_full_reuse_distance_histograms[] one histogram per set
            each per-set histogram contains the actual reuse distances for each sample
            in the set. This is measured by using the full trace to determine how many
            accesses actually went to the same set for a given sample. This does not
            need to be scaled.
            
    full_set_access_histograms[] per burst
        burst_full_set_access_histogram[]
            each bin contains the actual number of accesses to that set as counted for
            all the memory references that happen between the start and end of the burst
            It is not dependent on the samples in the burst -- this needs to be done separately.
    


'''

import pyusf
import sys
import histogram
import math
import time

class Associative_Cache:
    already_printed_quantitization_warning = False
    
    def print_and_exit(self, s):
        print "ERROR:" + s
        print >> sys.stderr, "ERROR:" + s
        sys.exit(1)
    
    def debug(self, string, level=1):
        if (level <= self.debug_level):
            s = ""
            if (level > 1):
                for x in range(0, level):
                    s += " "
            print s + string
    
    # Defines the cache in terms of size, bytes per line, number of entries per set (associativity),
    # whether or not dangling references should be counted when analyzing, and the debug level.
    def __init__(self, size_bytes, line_size_bytes, associativity=0, number_of_sets=0, count_dangling=True, debug=1):
        self.debug_level = debug
        self.count_dangling = count_dangling
        # Verify that there are a whole number of lines in the cache
        if (size_bytes % line_size_bytes != 0):
            self.print_and_exit("Invalid line size for cache size: " + str(size_bytes) + "%" + str(line_size_bytes) + "!=0")
        self.size_bytes = int(size_bytes)
        self.line_size_bytes = int(line_size_bytes)
        self.number_of_lines = self.size_bytes/self.line_size_bytes
        
        # Fully associative
        if (associativity == -1):
            number_of_sets = 1
            associativity = 0
        
        # Determine associativity and number of sets depending on what was provided
        # The user can provide one or the other or both
        if (associativity == 0 and number_of_sets == 0):
            self.print_and_exit("Either associativity or number_of_sets must be defined.")
        if (associativity != 0):
            self.associativity = int(associativity)
        if (number_of_sets != 0):
            self.number_of_sets = int(number_of_sets)
        
        if (associativity != 0 and number_of_sets == 0):
            self.number_of_sets = self.number_of_lines/self.associativity
        if (associativity == 0 and number_of_sets != 0):
            self.associativity = self.number_of_lines/self.number_of_sets
        # Verify that there are a whole number of sets in the cache
        if (self.number_of_lines % self.associativity != 0):
            self.print_and_exit("Invlalid associativity for number of lines: " + str(self.number_of_lines) + "%" + str(self.associativity) + "!=0")
        if (associativity != 0 and number_of_sets !=0):
            if (number_of_sets != self.number_of_lines/associativity):
                self.print_and_exit("Incomapatible number of sets and associativity for this size.")
            if (associativity != self.number_of_lines/number_of_sets):
                self.print_and_exit("Incompatible number of sets and associativity for this size.")
        
                
        
        
        # Calculate the number of bits and a mask for the line
        self.cache_line_bits_mask = self.line_size_bytes-1
        self.cache_line_bits = int(math.log(self.line_size_bytes, 2))
        if (self.cache_line_bits != math.log(self.line_size_bytes, 2)):
            self.print_and_exit("Invalid cache size: non-power-of-two line size.")
        
        # Calculate the number of bits and a mask for the set
        self.cache_set_bits_mask = self.number_of_sets-1 << self.cache_line_bits
        self.cache_set_bits = int(math.log(self.number_of_sets, 2))
        if (self.cache_set_bits != math.log(self.number_of_sets, 2)):
            self.print_and_exit("Invalid cache size: non-power-of-two associativity.")

        self.debug("Created cache:\n"+str(self), 1)

    # Returns information about the cache configuration as a string
    def __str__(self):
        s = ""
        s += "\tSize: " + str(self.size_bytes) + " (" + str(self.size_bytes/1024.0) + "kB), "
        s += "Line Size: " + str(self.line_size_bytes) +" (" + str(self.number_of_lines) + " lines), "
        s += "Associativity: " + str(self.associativity) + " (" + str(self.number_of_sets) + " sets of " +\
             str(self.number_of_lines/self.number_of_sets) + " lines), "
        s += " Line bit mask: 0x%X (%d bits), Set bit mask: 0x%X (%d bits)" % \
                    (self.cache_line_bits_mask, self.cache_line_bits, self.cache_set_bits_mask, self.cache_set_bits)
        return s

    def print_header(self, usf):
        header = usf.header
        version_major = (header.version >> 16) & 0xffff
        version_minor = header.version & 0xffff
    
        def line_sizes(line_size_mask):
            s = ""
            for i in range(32):
                if line_size_mask & (1 << i):
                    s += "%s " % (1 << i)
            return s.strip()
    
        s = "Header:"
        s+= "\tVersion: %d.%d" % (version_major, version_minor)
        s+= "\tCompression: %d (%s)" % (header.compression,
                                          pyusf.strcompr(header.compression))
        s+= "\tFlags: 0x%.8x" % (header.flags)
        s+= "\tSampling time: %d-%d" % (header.time_begin, header.time_end)
        s+= "\tLine sizes: %s" % (line_sizes(header.line_sizes))
        return s


    # Loads the two USF files for the full trace and the sampled version
    def load_usf_files(self, full_trace_usf_file_name, sampled_trace_usf_file_name, quiet=False):
        t0 = time.time()
        self.full_trace_usf_file_name = full_trace_usf_file_name
        self.sampled_trace_usf_file_name = sampled_trace_usf_file_name
        try:
            self.full_trace_usf = pyusf.Usf()
            self.full_trace_usf.open(self.full_trace_usf_file_name)
        except IOError, e:
            self.print_and_exit("Failed to load full trace USF file " + self.full_trace_usf_file_name + ":" + str(e))
        
        if not self.full_trace_usf.header.flags & pyusf.USF_FLAG_TRACE:
            self.print_and_exit("Full trace is not a trace file.")
        
        
        try:
            self.sampled_trace_usf = pyusf.Usf()
            self.sampled_trace_usf.open(self.sampled_trace_usf_file_name)
        except IOError, e:
            self.print_and_exit("Failed to load sampled trace USF file " + self.sampled_trace_usf_file_name + ":" + str(e))
            
        if self.sampled_trace_usf.header.flags & pyusf.USF_FLAG_TRACE:
            self.print_and_exit("Sampled trace is a trace file and not a sampled file")
    
        if not quiet:
            self.debug("Full " + self.print_header(self.full_trace_usf), 2)
            self.debug("Sampled " +self.print_header(self.sampled_trace_usf), 2)
            self.debug("\tLoaded trace files: full: " + self.full_trace_usf_file_name + " sampled: " + self.sampled_trace_usf_file_name \
                       + " in " + str(round(time.time()-t0,2)) + "s.", 1)

    # Closes and re-loads the USF files. Needed if we want to reset the iterator
    def reload_usf_files(self):
        self.full_trace_usf.close()
        self.sampled_trace_usf.close()
        self.load_usf_files(self.full_trace_usf_file_name, self.sampled_trace_usf_file_name, quiet=True)

    # Calculates the line for a given address
    def line_for_address(self, address):
        return address & self.cache_line_bits_mask

    # Calculates the set for a given address
    def set_for_address(self, address):
        # And with the mask to keep just the bits we want, then shift over to remove the lines
        return (address & self.cache_set_bits_mask) >> self.cache_line_bits
        
        
    # Goes through the bursts and determines which addresses will be sampled. Then it goes through
    # all samples in the full trace and determines the access count for each set at each point
    # to be sampled. This data can then be used to calculate the actual number of accesses to each
    # set between two accesses.
    def precompute_set_reuse_distances(self):
        tstart = time.time()
        self.full_set_access_counts = histogram.Hist()
        trigger_times = {} #time -> address
        self.full_sample_set_counts ={} # time -> (address,set-count) 
        
        # Find all the sample time/addresses we need to watch
        self.debug("Scanning through sampled trace to determine watched addresses...",2)
        t0 = time.time()
        for event in self.sampled_trace_usf:
            # Skip burst events
            if isinstance(event, pyusf.Burst):
                continue
            # Otherwise we need to watch the begin of the sample
            trigger_times[event.begin.time] = event.begin.addr
            # If it is a sample (i.e., not dangling) we need to watch the end as well
            if isinstance(event, pyusf.Sample):
                trigger_times[event.end.time] = event.end.addr
                
        self.debug("\tFound " + str(len(trigger_times)) + " watched addresses in " + str(round(time.time()-t0,2)) + "s.", 2)
        
        # Go through the full trace and do two things:
        # 1) keep track of the accesses to each set
        # 2) for each time/address we need to watch, record the accesses to that set when it happens
        self.debug("Scanning through full trace to determine set accesses at each sampled address...",2)
        t0 = time.time()
        for event in self.full_trace_usf:
            if isinstance(event, pyusf.Trace):
                # Get the set for this access
                set = self.set_for_address(event.access.addr)
                # Count it
                self.full_set_access_counts.add(set)
                # If we are watching this time and the address matches then record its set count and
                # stop watching it
                if trigger_times.has_key(event.access.time):
                    # Make sure the time matches the expected address
                    if (trigger_times[event.access.time] != event.access.addr):
                        self.print_and_exit("Access at time " + str(event.access.time) + " does not match expected address: " \
                                            + str(event.acccess.addr) + " != " + trigger_times[event.access.time])
                    # Make sure we don't already have this time recorded
                    if (event.access.time in self.full_sample_set_counts.keys()):
                        self.print_and_exit("Access time " + str(event.access.time) + " is already in the " \
                                            + " full sample set counts as " + str(self.full_sample_set_counts[event.access.time]))
                    # Record the data for this access time
                    self.full_sample_set_counts[event.access.time] = (event.access.addr, self.full_set_access_counts[set])
                    # Remove this time from the list of events to check
                    del trigger_times[event.access.time]

        
        self.debug("\tDone scanning for set accesses for all memory samples in " + str(round(time.time()-t0,2)) + "s.", 2)
        
        # Close and re-open the traces
        self.reload_usf_files()
        self.debug("\tPre-computed baseline set reuse distances in " + str(round(time.time()-tstart,2)) + "s.", 1)
        
        return
        
    # Walks through the full trace and generates a set access histogram from the burst_start_time to
    # the burst_end_time using all samples. This is the true access histogram as opposed to the
    # sampled one.
    def generate_full_trace_set_access_histogram(self, burst_start_time, burst_end_time, set_access_histogram):
        # Iterate through the full trace until we get to the start_time
        this_time = 0
        # FIXME: We need to close/open the USF file every time to make sure we don't miss things here
        self.reload_usf_files()
        for event in self.full_trace_usf:
            if isinstance(event, pyusf.Trace):
                this_time = event.access.time
                if (this_time < burst_start_time):
                    continue
                
                access_set = self.set_for_address(event.access.addr)
                set_access_histogram.add(access_set)
                
                if (this_time == burst_end_time):
                    return
        self.debug("Warning: ran out of samples in the full trace before reaching the burst end time:"\
                   + " last sample in trace: " + str(this_time) + " but burst end time was: " + \
                   str(burst_end_time),0)
        return
    
    # Goes through the samples and generates the histogram data including:
    # for each burst:
    # - the access counts for each set from the samples
    # - the access counts for each set from the full trace
    # - for each set:
    #   - the reuse distance histogram from the samples (raw access time deltas)
    #   - the reuse distance histogram from the full trace (actual reuse distance)
    def process(self):
        try:
            self.full_sample_set_counts
        except NameError:
            self.print_and_exit("The set reuse distance has not been computed before calling process.")

        if (not self.count_dangling):
            self.debug("Note: NOT counting Dangling references.", 0)
        # Per burst data:
        #  The reuse distance histograms from the sampled data (unscaled)
        self.sampled_reuse_distance_histograms = []
        #  The set access histograms from the sampled data
        self.sampled_set_access_histograms = []
        #  The real reuse distance histograms from the raw data (exact per-set distances)
        self.full_reuse_distance_histograms = []
        #  The real set access histograms from the raw data (all accesses int the burst included)
        self.full_set_access_histograms = []
        
#        # Get an interator for the full trace
#        full_trace_iterator = self.full_trace_usf.__iter__().__iter__()

        
        current_burst = -1
        current_burst_sample = 0
        total_samples = 0
        total_skipped_dangling = 0
        # We need to track the burst start/end time so we know how much of the full trace
        # to walk through to get the actual set access histogram
        burst_start_times = []
        burst_end_times = []
        # Go through the sampled trace
        t0 = time.time()
        for event in self.sampled_trace_usf:
            # For each burst in the sampled trace weadd new structures to the per-burst data
            if isinstance(event, pyusf.Burst):
                if (current_burst > 0):
                    self.debug("Burst " + str(current_burst) + " start: " + str(burst_start_times[current_burst]) + " end: " + str(burst_end_times[current_burst]) + \
                               " with " + str(current_burst_sample) + " samples.", 3)
                current_burst += 1
                current_burst_sample = 0
                burst_start_times.append(event.begin_time)
                burst_end_times.append(event.begin_time)
                
                # Each gets one histogram per set
                burst_sampled_reuse_distance_histograms_per_set = []
                burst_full_reuse_distance_histograms_per_set = []
                for x in range(0, self.number_of_sets):
                    burst_sampled_reuse_distance_histograms_per_set.append(histogram.Hist())
                    burst_full_reuse_distance_histograms_per_set.append(histogram.Hist())
                self.sampled_reuse_distance_histograms.append(burst_sampled_reuse_distance_histograms_per_set)
                self.full_reuse_distance_histograms.append(burst_full_reuse_distance_histograms_per_set)
                # The access histograms are one per burst    
                burst_sampled_set_access_histogram = histogram.Hist()
                self.sampled_set_access_histograms.append(burst_sampled_set_access_histogram)
                burst_full_set_access_histogram = histogram.Hist();
                self.full_set_access_histograms.append(burst_full_set_access_histogram)
                
                # We don't do anything for the burst per se, so continue
                continue
            
            total_samples += 1
            # Update the set access histogram with the address accessed
            # Get the address and set
            # Note: do I need to do something special with the length?
            sample_address = event.begin.addr
            # Get the set and update the set access histogram
            sample_set = self.set_for_address(sample_address)
            burst_sampled_set_access_histogram.add(sample_set)
            
            # Get the reuse distance
            if isinstance(event, pyusf.Sample):
                sample_reuse_distance = event.end.time - event.begin.time - 1
            elif isinstance(event, pyusf.Dangling):
                if (not self.count_dangling):
                    total_skipped_dangling += 1
                    continue
                # Why is this done for Dangling? Doesn't this bias the histograms terribly?
                sample_reuse_distance = sys.maxint
            else:
                self.print_and_exit("Unexpected event type: " + str(type(event)))
            # Record the reuse distance
            burst_sampled_reuse_distance_histograms_per_set[sample_set].add(sample_reuse_distance)
            
            # Check if this is the latest start address in the burst
            if (event.begin.time > burst_end_times[current_burst]):
                burst_end_times[current_burst] = event.begin.time
            
            # Find the actual reuse distance from the pre-scanned data
            # Begin data is the same for both Samples and Dangling
            (begin_address, begin_set_count) = self.full_sample_set_counts[event.begin.time]
            if (begin_address != event.begin.addr):
                self.print_and_exit("Event address does not match address in full sample set counts")
            # End data is different for Samples and Dangling
            # Samples have their end data recorded for a particular time/address
            # Dangling have an "infinite" reuse distance
            if isinstance(event, pyusf.Sample):
                (end_address, end_set_count) = self.full_sample_set_counts[event.end.time]
                if (end_address != event.end.addr):
                    self.print_and_exit("Event address does not match address in full sample set counts")
                actual_set_accesses = end_set_count - begin_set_count - 1
            elif isinstance(event, pyusf.Dangling):
                actual_set_accesses = sys.maxint
            # Calcualte and record the actual reuse distance
            burst_full_reuse_distance_histograms_per_set[sample_set].add(actual_set_accesses)

            self.debug("> Sample " + str(current_burst_sample) + ":\t addr=" + str(sample_address) + \
                       ", set=" + str(sample_set) + ", raw dist=" + str(sample_reuse_distance) + \
                       ", real dist=" + str(actual_set_accesses) + ", time=" + str(event.begin.time), 4)
            current_burst_sample += 1
            
        self.debug("Burst " + str(current_burst) + " start: " + str(burst_start_times[current_burst]) + " end: " + str(burst_end_times[current_burst]) + \
                               " with " + str(current_burst_sample) + " samples.", 3)
        # Now we have the burst_start_times and burst_end_times for all bursts
        # so we can go through the full trace and determine the full_set_access_histograms
        for burst in range(0, len(burst_start_times)):
            self.generate_full_trace_set_access_histogram(burst_start_times[burst], burst_end_times[burst], \
                                                            self.full_set_access_histograms[burst])

        self.debug("\tDone processing " + str(total_samples) + " total samples (" + str(current_burst+1) + " bursts) in " +
                   str(round(time.time()-t0,2)) + "s. (skipped " + str(total_skipped_dangling) + " dangling samples)", 0)
        return
    
    # Verifies that each of the reuse distance histograms from the raw data contain the same number of 
    # entries as the ones that contain the true reuse distances.
    def verify_reuse_distance_sampled_vs_full(self):
        verified = True
        for burst in range(0, len(self.sampled_reuse_distance_histograms)):
            for set_number in range(0, self.number_of_sets):
                sampled_total = sum(self.sampled_reuse_distance_histograms[burst][set_number].values())
                full_total = sum(self.full_reuse_distance_histograms[burst][set_number].values())
                if (sampled_total != full_total):
                    verified = False
                    print "Burst " + str(burst) + " set " + str(set_number) + " failed to verify: " + \
                        "Sampled: " + str(sampled_total)+ " != Full: " + str(full_total)
        if (verified):
            self.debug("Verified reuse distance histograms contain the same number of entries for sampled and full sets.")
        return verified
                        
       
    
    def dump_histograms(self):
        s = ""
        for burst in range(0, len(self.sampled_reuse_distance_histograms)):
            s += " Burst " + str(burst) + "\n"
            s += "\tsampled reuse distance histogram:\n" #+ str(self.sampled_reuse_distance_histograms[burst]) +"\n"
            for set_number in range(0, self.number_of_sets):
                s += "=== SAMPLED Reuse Distance Histogram Set " + str(set_number) + "\n" + str(self.sampled_reuse_distance_histograms[burst][set_number])           
                s += "=== FULL Reuse Distance Histogram Set " + str(set_number) + "\n" + str(self.full_reuse_distance_histograms[burst][set_number])           
            s += "\tsampled set access histogram:\n" + str(self.sampled_set_access_histograms[burst]) +"\n"
            s += "\tfull set access histogram:\n" + str(self.full_set_access_histograms[burst]) +"\n"
        return s
    
    
    # Calculates the scale factor for each entry as that entry's percentage of
    # the total values. E.g., for each set, this returns the percentage of the
    # total accesses that went to that set.
    def determine_set_scaling_factors(self, set_access_histogram):#, prescaled=False):
        scaled = {}
        total = float(sum(set_access_histogram.hist.values()))
        for set in range(0, self.number_of_sets):
            if set in set_access_histogram.hist.keys():
                scaled[set] = set_access_histogram[set]/total
            else:
                scaled[set] = 0.0
        return scaled
    
    # Scales a set reuse distance histogram's reuse distances by the provided scale factor
    # and returns a new histogram with those scaled distances added to integer reuse distances.
    # E.g., if a reuse distance of 54 is scaled by 0.05 to 2.7, the counts for that bin will
    # be put in the new histogram in bin floor(2.7)=2.
    def scale_and_resample_set_histogram(self, unscaled_set_reuse_histogram, scale_factor, prescaled=False):
        new_hist = histogram.Hist()
        if not self.already_printed_quantitization_warning:
            self.debug("WARNING: quantitization when resampling the reuse histogram may be a big problem.", 0)
            self.already_printed_quantitization_warning = True
        # If it is pre-scaled do nothing
        if prescaled:
            for v, c in unscaled_set_reuse_histogram: 
                new_hist.add(v, c)
            return new_hist
        # Otherwise scale and insert into the histogram
        for v, c in unscaled_set_reuse_histogram: 
            if v == sys.maxint:
                scaled_v = v
            else:
                scaled_v = int(math.floor(v*scale_factor))
            new_hist.add(scaled_v, c)
        return new_hist
    
    # Goes through all the unscaled histograms for all sets and scales them based on the set usages
    # defined in the provided set access histogram. 
    def scale_and_resample_all_set_histograms(self, set_access_histogram, unscaled_set_reuse_histograms, prescaled=False):
        scale_factors = self.determine_set_scaling_factors(set_access_histogram)
        scaled_set_reuse_histograms = []
        for i in range(0, self.number_of_sets):
            #if i in scale_factors:
            scaled_set_reuse_histograms.append(self.scale_and_resample_set_histogram( \
                        unscaled_set_reuse_histograms[i], scale_factors[i], prescaled))
            #else:
            #    scaled_set_reuse_histograms.append(histogram.Hist())
        return (scale_factors, scaled_set_reuse_histograms)
        

    # This method calculates the overall missrate for a burst given its set access histogram
    # and a set reuse histogram. The set access histogram is used to scale and resample
    # the set reuse histogram which is then fed into the lrumodel from David E.
    def calculate_miss_ratio_for_all_sets(self, set_access_histogram, unscaled_set_reuse_histogram, prescaled=False):
        set_miss_rates = {}
        (set_scaling_factors, scaled_set_reuse_histograms) = \
            self.scale_and_resample_all_set_histograms(set_access_histogram, unscaled_set_reuse_histogram, prescaled)
        for set in range(0, self.number_of_sets):
            # Skip if we don't have any set data for this set
            #if not set in set_scaling_factors:
            #    continue
            # lrumodel shoudl take a histogram okay, but apparently not
            scaled_set_reuse_histogram = scaled_set_reuse_histograms[set]
            #print scaled_set_reuse_histogram
            if (len(scaled_set_reuse_histogram) == 0):
                self.debug("Set " + str(set) + " miss ratio: 0.0 (no accesses to set)", 4)
                continue
            # FIXME: we should not have to do this, but lrumodel does not work with Histograms for some reason
            blah = {}
            for k,v in scaled_set_reuse_histogram:
                blah[k]=v
            set_miss_rates[set] = lrumodel.miss_ratio(blah)#scaled_set_reuse_histogram)
            # FIXME: Is the missrate for byte size or number of lines? self.line_size_bytes*
            self.debug("Set " + str(set) + " miss ratio: " + str(set_miss_rates[set][self.associativity]), 4)
        return (set_miss_rates, set_scaling_factors)

    # Uses the provided set missrates to calculate the total missrate for a given set of cache sizes
    def calculate_total_miss_ratios_for_cache(self, set_miss_rates, set_scaling_factors):
        total_miss_ratio = 0.0
        set_miss_ratios = {}
        for set in range(0, self.number_of_sets):
            # Note: the set not in set_miss_rates is needed if you use the full histogram with the sampled data
            if (set_scaling_factors[set] == 0 or set not in set_miss_rates):
                set_miss_ratios[set] = 0.0
                continue
            set_miss_ratio_for_size = set_miss_rates[set][self.associativity] # FIXME: Is this bytes size or number of lines? self.line_size_bytes*
            # Scale the portion of this miss ratio that goes towards the total miss ratio by the portion of
            # accesses it represents.
            total_miss_ratio += set_miss_ratio_for_size*set_scaling_factors[set]
            set_miss_ratios[set] = set_miss_ratio_for_size
        self.debug("Miss ratio for cache size " + str(self.size_bytes) + " (" + str(self.number_of_sets) + \
                   "*" + str(self.line_size_bytes*self.associativity) + "B sets) is " + str(total_miss_ratio), 4)
        return (total_miss_ratio, set_miss_ratios)
    
    
    def print_scale_factors_csv(self, round_amount=4):
        t0 = time.time()
        burst_sampled_sampled_total_miss_ratios = {}
        burst_full_full_total_miss_ratios = {}
        burst_full_sampled_total_miss_ratios = {}
        result = "burst,\tset,\tss miss ratio,\tfs miss ratio,\tff miss ratio,\titems,\tdangling,\tscale,\traw mean,\tscaled mean,\tfull mean,\traw stdev,\tscale stdev,\tfull stdev\n"
        ignore_list = [sys.maxint] # Ignore samples that don't finish in the statistics
        for burst in range(0, len(self.sampled_reuse_distance_histograms)):
            (factors, scaled) = self.scale_and_resample_all_set_histograms(self.sampled_set_access_histograms[burst], self.sampled_reuse_distance_histograms[burst])
            
            # Calculate the miss ratios for the sampled sets with sampled set scaling factors
            (sampled_sampled_set_miss_rates, sampled_sampled_set_scaling_factors) = \
                self.calculate_miss_ratio_for_all_sets(self.sampled_set_access_histograms[burst], self.sampled_reuse_distance_histograms[burst])
            (sampled_sampled_total_miss_ratio, sampled_sampled_set_miss_ratios) = \
                self.calculate_total_miss_ratios_for_cache(sampled_sampled_set_miss_rates, sampled_sampled_set_scaling_factors)
            burst_sampled_sampled_total_miss_ratios[burst] = sampled_sampled_total_miss_ratio

            # Calculate the miss ratios using the full set access histograms and the sampled reuse distances
            (full_sampled_set_miss_rates, full_sampled_set_scaling_factors) = \
                self.calculate_miss_ratio_for_all_sets(self.full_set_access_histograms[burst], self.sampled_reuse_distance_histograms[burst])
            (full_sampled_total_miss_ratio, full_sampled_set_miss_ratios) = \
                self.calculate_total_miss_ratios_for_cache(full_sampled_set_miss_rates, full_sampled_set_scaling_factors)
            burst_full_sampled_total_miss_ratios[burst] = full_sampled_total_miss_ratio
            
            # Calculate the miss ratios using the full set access histograms and the full reuse distances
            (full_full_set_miss_rates, full_full_set_scaling_factors) = \
                self.calculate_miss_ratio_for_all_sets(self.full_set_access_histograms[burst], self.full_reuse_distance_histograms[burst], prescaled=True)
            (full_full_total_miss_ratio, full_full_set_miss_ratios) = \
                self.calculate_total_miss_ratios_for_cache(full_full_set_miss_rates, full_full_set_scaling_factors)
            burst_full_full_total_miss_ratios[burst] = full_full_total_miss_ratio
            
            
            for set in range(0, len(scaled)):
                # Burst
                result += str(burst) + ",\t"
                # Set
                result += str(set) + ",\t"
                # Miss rates
                for data in [sampled_sampled_set_miss_ratios, full_sampled_set_miss_ratios, full_full_set_miss_ratios]:
                    result += str(round(data[set], round_amount)) + ",\t\t"
                # Number of samples
                result += str(scaled[set].count_entries(ignore_list)) + ",\t"
                # Number of dangling samples
                result += str(scaled[set].count_entries()-scaled[set].count_entries(ignore_list)) +",\t\t"
                # Scaling factor
                if (set in factors):
                    result += str(round(factors[set], round_amount)) + ",\t"
                else:
                    result += " ,\t"
                    continue
                # Mean
                for data in [self.sampled_reuse_distance_histograms[burst][set], scaled[set], self.full_reuse_distance_histograms[burst][set]]:
                    result += str(round(data.mean(ignore_list), round_amount)) + ",\t"
                # Stdev
                for data in [self.sampled_reuse_distance_histograms[burst][set], scaled[set], self.full_reuse_distance_histograms[burst][set]]:
                    result += str(round(data.stdev(ignore_list), round_amount)) + ",\t"
                result += "\n"
            
        result += "burst,\tss miss ratio,\tfs miss ratio,\tff miss ratio\n"    
        for burst in range(0, len(self.sampled_reuse_distance_histograms)):
            result += str(burst) +",\t"
            for data in [burst_sampled_sampled_total_miss_ratios, burst_full_sampled_total_miss_ratios, burst_full_full_total_miss_ratios]:
                result += str(round(data[burst], round_amount)) +",\t\t"
            result += "\n"
        self.debug("Formatted detailed output data in " + str(round(time.time()-t0,2)) + "s (" + str(round(len(result)/1024.0,2)) + "kB)", 0)
        return result
    
    # Goes over all bursts and calculates the three miss ratios
    def calculate_all_miss_ratios(self):
        ss_ratio = [0.0] # Miss ratio for sampled fset access and sampled reuse distance
        fs_ratio = [0.0] # Miss ratio for actual set access and sampled reuse distance
        ff_ratio = [0.0] # Miss ratio for actual set access and actual reuse distance
        pairs = [\
                 (self.sampled_set_access_histograms, self.sampled_reuse_distance_histograms, False, ss_ratio), \
                 (self.full_set_access_histograms, self.sampled_reuse_distance_histograms, False, fs_ratio), \
                 (self.full_set_access_histograms, self.full_reuse_distance_histograms, True, ff_ratio) \
                 ]

        for (access_histograms, distance_histograms, prescaled, ratio) in pairs:
            for burst in range(0, len(self.sampled_reuse_distance_histograms)): 
                (set_miss_rates, set_scaling_factors) = self.calculate_miss_ratio_for_all_sets(access_histograms[burst], distance_histograms[burst], prescaled)
                (total_miss_ratio, set_miss_ratios) = self.calculate_total_miss_ratios_for_cache(set_miss_rates, set_scaling_factors)
                ratio[0] += total_miss_ratio

        number_of_bursts = len(self.sampled_reuse_distance_histograms)
        return (ss_ratio[0]/number_of_bursts, fs_ratio[0]/number_of_bursts, ff_ratio[0]/number_of_bursts)

def run_model(size_bytes, line_size_bytes, associativity, trace_usf_file, sampled_usf_file, output_file = None, debug_level=2):   
    t0 = time.time()
    c = Associative_Cache(size_bytes=size_bytes, line_size_bytes=line_size_bytes, associativity=associativity, debug=debug_level)
    t1 = time.time()
    c.load_usf_files(trace_usf_file, sampled_usf_file)
    t2 = time.time()
    c.precompute_set_reuse_distances()
    t3 = time.time()
    c.process()
    t4 = time.time()
    if (output_file != None):
        result = c.print_scale_factors_csv(5)
        f = open(output_file, "w")
        f.write(result)
        f.close()
    t5 = time.time()
    result = c.calculate_all_miss_ratios()
    t6 = time.time()
    
    t0 = t1-t0
    t1 = t2-t1
    t2 = t3-t2
    t3 = t4-t3
    t4 = t5-t4
    t5 = t6-t5
    print "Cache %dkB/%d: time: create (%f), load (%f), precompute (%f), process (%f), output (%f), calculate (%f)\n" % \
        (size_bytes/1024.0, associativity, t0, t1, t2, t3, t4, t5)
    
    return result
    
def test():
    c = Associative_Cache(size_bytes=1024*1.0, line_size_bytes=16, number_of_sets=4, debug=3)
#    c.load_usf_files("/home/dbs/usf-traces/bzip2.usf", "/home/dbs/usf-traces/bzip2.usf.sampled.sorted.0")
    c.load_usf_files("/home/dbs/usf-traces/bzip2.usf", "/home/dbs/usf-traces-sampled/rate_1_100_300/bzip2/bzip2_0.usf")
    c.precompute_set_reuse_distances()
    c.process()
    c.verify_reuse_distance_sampled_vs_full()
    print c.print_scale_factors_csv()
    
#    (factors, scaled) = c.scale_and_resample_all_set_histograms(c.sampled_set_access_histograms[0], c.sampled_reuse_distance_histograms[0])
##    for i in range(0, len(scaled)):
##        print "==== Set: " + str(i)
##        if (i in factors):
##            print " scale factor: " + str(factors[i])
##        else:
##            print " emtpy."
##            continue
##        print "(raw)"
##        print c.sampled_reuse_distance_histograms[0][i].stats([sys.maxint])
##        print c.sampled_reuse_distance_histograms[0][i]
##        print "(scaled)"
##        print scaled[i].stats([sys.maxint])
##        print scaled[i]
##        print "(full)"
##        print c.full_reuse_distance_histograms[0][i].stats([sys.maxint])
##        print c.full_reuse_distance_histograms[0][i]
#    
#    for i in range(0, len(scaled)):
#        print "==== Set: " + str(i),
#        if (i in factors):
#            print " scale factor: " + str(factors[i])
#        else:
#            print " emtpy."
#            continue
#        print "   (raw)     ", c.sampled_reuse_distance_histograms[0][i].stats([sys.maxint])
#        print "   (scaled)  ", scaled[i].stats([sys.maxint])
#        print "   (full)    ", c.full_reuse_distance_histograms[0][i].stats([sys.maxint])
#    
#    (set_miss_rates, set_scaling_factors) = \
#        c.calculate_miss_ratio_for_all_sets(c.sampled_set_access_histograms[0], c.sampled_reuse_distance_histograms[0])
#    print "Scale factors:", str(set_scaling_factors)
#    (total_miss_ratio, set_miss_ratios) = c.calculate_total_miss_ratios_for_cache(set_miss_rates, set_scaling_factors)
#    print "Sampled Total miss ratio: " + str(total_miss_ratio)
#    for set, ratio in set_miss_ratios.items():
#        print " sampled set " + str(set) + " miss ratio: " + str(round(ratio,3))
#        
#        
#    # Define scale factors for the actual measurements
#    (full_set_miss_rates, full_set_scaling_factors) = \
#        c.calculate_miss_ratio_for_all_sets(c.full_set_access_histograms[0], c.full_reuse_distance_histograms[0], prescaled=True)
#    print "Full reuse distance scale factors:", str(full_set_scaling_factors)
#    (full_total_miss_ratio, full_set_miss_ratios) = c.calculate_total_miss_ratios_for_cache(full_set_miss_rates, full_set_scaling_factors)
#    print "Full Total miss ratio: " + str(full_total_miss_ratio)
#    for set, ratio in full_set_miss_ratios.items():
#        print " full set " + str(set) + " miss ratio: " + str(round(ratio,3))
     
        
    
    #print c.dump_histograms()
    
if __name__ == "__main__":
    test()

