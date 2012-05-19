# Configurations for a modeling run.
# Note this is a standard python file that will be evaluated with exec().
#

#
# Run configuration
#

# Number of different samplings to use
config.number_of_samplings = 2

# Parameters for each sampling
# (sample period, burst period, burst length)
config.sampling_definitions = [(0,0,10000000),(100, 100, 100)] # (0, 0, 1000000), 

# Cache sizes
config.cache_sizes = [1024, 1024*64, 1024*128]

# Cache associativities
config.cache_associativities = [1, 2, 16]

# Short name for this set of parameters
config.short_name = "test"

# Line size
config.line_size = 16

config.force_create = False

#
# File locations
#

# List of benchmark names
config.benchmark_names = ["bzip2", "gcc", "libquantum", "perlbench", "soplex"]

# Full benchmark usf file directory
config.raw_benchmark_usf_path = "/home/dbs/usf-traces"

# Sampled benchmark usf file directory
config.sampled_benchmark_usf_path = "/home/dbs/usf-traces-sampled"

# Output directory
config.output_path = "/home/dbs/output"



#
# Binary locations
#

# Path to cache simulator
config.cache_simulator_path = "/home/dbs/workspace/StatCache/src/trunk/cachesim/cache/usf_sim"

# Path to cache model
config.cache_model_path = "/home/dbs/workspace/StatCache/src/trunk/analysis/lru_associative.py"

# Path to usf_sampler
config.usfsampler_path = "/home/dbs/workspace/StatCache/src/trunk/sampler/usf_sampler"

# Path to usfsort
config.usfsort_path = "/usr/local/bin/usfsort"

# Path to usfcat
config.usfcat_path = "/usr/local/bin/usfcat"

