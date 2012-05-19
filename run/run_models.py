import lru_associative
import os, sys, subprocess, tempfile, re

debug_level = 3

class run_config:
    number_of_samplings = 0
    sampling_definitions = []
    cache_sizes = []
    cache_associativities = []
    short_name = ''
    line_size = 0
    benchmark_names = []
    raw_benchmark_usf_path = ''
    sampled_benchmark_usf_path = ''
    output_path = ''
    cache_simulator_path = ''
    cache_model_path = ''
    usfsampler_path = ''
    usfsort_path = ''
    usfcat_path = ''
    
    def __str__(self):
        s = "config.number_of_samplings = " + str(self.number_of_samplings) +"\n"
        s += "config.sampling_definitions = " + str(self.sampling_definitions) +"\n"
        s += "config.cache_sizes = " + str(self.cache_sizes) +"\n"
        s += "config.cache_associativities = " + str(self.cache_associativities) +"\n"
        s += "config.short_name = " + str(self.short_name) +"\n"
        s += "config.line_size = " + str(self.line_size) +"\n"  
        s += "--\n"
        s += "config.force_create = " + str(self.force_create) +"\n"
        s += "config.benchmark_names = " + str(self.benchmark_names) +"\n"
        s += "config.raw_benchmark_usf_path = " + str(self.raw_benchmark_usf_path) +"\n"
        s += "config.sampled_benchmark_usf_path = " + str(self.sampled_benchmark_usf_path) +"\n"
        s += "config.output_path = " + str(self.output_path) +"\n"
        s += "--\n"
        s += "config.cache_simulator_path = " + str(self.cache_simulator_path) +"\n"    
        s += "config.cache_model_path = " + str(self.cache_model_path) +"\n"    
        s += "config.usfsampler_path = " + str(self.usfsampler_path) +"\n"    
        s += "config.usfsort_path = " + str(self.usfsort_path) +"\n"    
        s += "config.usfcat_path = " + str(self.usfcat_path) +"\n"  
        return s  

def print_and_exit(error):
    print >> sys.stderr, "ERROR:" + error
    sys.exit(1)
    
    
def debug(string, level=1):
    global debug_level
    if (level <= debug_level):
        s = ""
        if (level > 1):
            for x in range(0, level):
                s += " "
        print s + string

def run_process(process):
    debug( "\tRunning: \"" + process + "\"",2)
    output = tempfile.NamedTemporaryFile()
    p = subprocess.Popen(process, stderr=output, stdout=output, shell=True)
    result = p.wait()
    output.flush()
    read_output = open(output.name, 'r')
    text = "Process returned: " + str(result) + "\n"
    for line in read_output.readlines():
        text = text + line
    return text

    
def load_config(config_file):
    debug("Loading config file " + config_file, 1)
    config = run_config()
    
    # Exec the config file to load it
    try:
        exec(open(config_file))
    except IOError, e:
        debug("Current working directory: " + os.getcwd(), 0)
        debug("Path: " + sys.path, 0)
        print_and_exit("Configuration Failure: IOError loading config file " + config_file + ":" + str(e))
 
    # Print out the loaded config for debugging
    debug("Configuration:\n" + str(config), 1)
    debug("Loaded config file " + config_file, 0)
    return config

# Generates the directory string to the sampled usf file for the specific config
# Note that you need to append .usf to get the actual file name
def get_usf_directory(config, sample_period, burst_period, burst_length, sample, benchmark):
    dir = config.sampled_benchmark_usf_path+"/rate_"+\
        str(sample_period) + "_" + str(burst_period) + "_" + str(burst_length) + \
        "/" + benchmark + "/" + benchmark + "_" + str(sample)
    return dir

# Does the actual usf sampling for one specific configuration
def do_sampling(config, sample_period, burst_period, burst_length, seed, benchmark, options={"remove_temp_files":True}):
    if "remove_temp_files" in options:
        remove_temp_files = options["remove_temp_files"]
    else:
        remove_temp_files = False
    
    raw_benchmark_path = config.raw_benchmark_usf_path + "/" + benchmark + ".usf"
    usf_path = get_usf_directory(config, sample_period, burst_period, burst_length, seed, benchmark)
    final_sorted_sample_file = usf_path+".usf"
    sampled_usf_file = usf_path + ".sampled.usf"
    sampled_usf_catted_unsorted = usf_path + ".unsorted.usf"
    
    # If it already exists (and we aren't forcing creation of new ones)
    # skip this one.
    if (not config.force_create and os.path.exists(final_sorted_sample_file)):
        debug(final_sorted_sample_file + " exists, skipping.", 1)
        return
    
    (directory_to_make, file) = os.path.split(final_sorted_sample_file)
    if not os.path.exists(directory_to_make):
        os.makedirs(directory_to_make)
    
    # Sample the file
    sample_command = config.usfsampler_path + " -i " + raw_benchmark_path + \
        " -o " + sampled_usf_file + " -s " + str(sample_period) + \
        " -S const -b " + str(burst_period) + " -B const -z " + str(burst_length) + \
        " -l " + str(config.line_size)
    result = run_process(sample_command)
    debug("\tSample command result: " + result, 2)
    
    # Cat the file
    cat_command = config.usfcat_path + " " + sampled_usf_file + ".* > " + sampled_usf_catted_unsorted 
    result = run_process(cat_command)
    debug("\tCat command result: " + result, 2)
                  
    # Delete all the non-cat'ed partial files
    if remove_temp_files:
        rm_command = "rm " + sampled_usf_file + ".*"
        result = run_process(rm_command)
        debug("\trm command result: " + result, 2)
                  
    # Sort the file
    sort_command = config.usfsort_path + " " + sampled_usf_catted_unsorted + " " + final_sorted_sample_file
    result = run_process(sort_command)
    debug("\tSort command result: " + result, 2)
    
    # Delete the non-sorted file
    if remove_temp_files:
        rm_command = "rm " + sampled_usf_catted_unsorted
        result = run_process(rm_command)
        debug("\trm command result: " + result, 2)


def do_model(config, sample_period, burst_period, burst_length, seed, benchmark, options):
    trace_usf = config.raw_benchmark_usf_path + "/" + benchmark + ".usf"
    sampled_usf = get_usf_directory(config, sample_period, burst_period, burst_length, seed, benchmark) + ".usf"
    result = "sample period,burst_period,burst_length,benchmark,seed,cache_size,associativity,ss miss ratio,fs miss ratio,ff miss ratio,baseline miss ratio\n"
    for cache_size in config.cache_sizes:
        for associativity in config.cache_associativities:
            # Run the model
            data_file = sampled_usf+"_size_" + str(cache_size) + "_assoc_" + str(associativity) + ".csv"
            data_file = None
            (ss_ratio, fs_ratio, ff_ratio) = lru_associative.run_model(cache_size, config.line_size, associativity, trace_usf, sampled_usf, data_file)
            
            # Run the cache simulator
            if (associativity == -1):
                sim_associativity = cache_size/config.line_size
            else:
                sim_associativity = associativity
            cache_sim_command = "%s -i %s/%s.usf -c %d -C %d -l %d -a %d" % \
                (config.cache_simulator_path, config.raw_benchmark_usf_path, benchmark, \
                 cache_size, cache_size, config.line_size, sim_associativity)
            cache_sim_result = run_process(cache_sim_command)
            sim_data = [0, 0, 0, 0]
            for k,v in {"rd_hits:\\s*(\\d+)":0, "wr_hits:\\s*(\\d+)":1, "rd_misses:\\s*(\\d+)":2, "wr_misses:\\s*(\\d+)":3}.items():  
                match = re.search(k, cache_sim_result)
                if (match):
                    sim_data[v] = int(match.group(1))
                else:
                    print_and_exit("Failed to find " + k + " in cache sim.")
            total_hits = float(sim_data[0]+sim_data[1])
            total_misses = float(sim_data[2]+sim_data[3])
            sim_miss_ratio = total_misses/(total_hits+total_misses)
            
            # Put the results in the output
            result += "%d,%d,%d,%s,%d,%d,%d,%f,%f,%f,%f\n" % \
            (sample_period, burst_period, burst_length, \
             benchmark, seed, \
             cache_size, associativity, \
             ss_ratio, fs_ratio, ff_ratio, sim_miss_ratio)
    print result
    return result

# Executes the operation on all configurations
def for_all_configs(config, operation, options={"remove_temp_files":True}):
    result = str(config) + "\n"
    for (sample_period, burst_period, burst_length) in config.sampling_definitions:            
        # For each benchmark
        for benchmark in config.benchmark_names:                
            debug("\tProcessing " + str(config.number_of_samplings) + " samplings for benchmark " + benchmark + \
                  " with rate (sample period: " + str(sample_period) + \
                  ", burst period: " + str(burst_period) + \
                  ", burst length: " + str(burst_length) +")",2)
            # For each seed
            for seed in range(0, config.number_of_samplings):
                returned = operation(config, sample_period, burst_period, burst_length, seed, benchmark, options)
                if (returned != None):
                    result += str(returned)
    return result

def main():
    # Parse the aruments
    config = load_config(sys.argv[1])
    for_all_configs(config, do_sampling)
    result = for_all_configs(config, do_model)
    print result










if __name__ == "__main__":
    main()