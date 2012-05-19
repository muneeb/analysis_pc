#ifndef LRU_MODEL_HH
#define LRU_MODEL_HH
#include <map>
#include <inttypes.h>
#include "lru_model.h"

typedef std::map<uint64_t, uint32_t> rdist_hist_t;

sdist_map_t lru_model(rdist_hist_t &rdist_hist, int count, int boundary);

#endif /* LRU_MODEL_HH */
