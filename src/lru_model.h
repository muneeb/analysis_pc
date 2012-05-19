#ifndef LRU_MODEL_H
#define LRU_MODEL_H
#include <uart/vect.h>
#include "hist.h"

typedef struct {
    float rdist;
    float sdist;
    float pdf;
    float mratio;
} sdist_map_elem_t;

typedef VECT(sdist_map_elem_t) sdist_map_t;

#define SDIST_MAP_NULL          VECT_NULL
#define SDIST_MAP_INIT(map)     VECT_INIT(map)
#define SDIST_MAP_FINI(map)     VECT_FINI(map)
#define SDIST_MAP_FOREACH(m, i) VECT_FOREACH(m, i)

#define SDIST_MAP_APPEND(map, _rdist, _sdist, _pdf, _mratio) do {       \
    sdist_map_elem_t map_elem;                                          \
    map_elem.rdist = _rdist;                                            \
    map_elem.sdist = _sdist;                                            \
    map_elem.pdf = _pdf;                                                \
    map_elem.mratio = _mratio;                                          \
    VECT_APPEND(map, map_elem);                                         \
} while (0)

sdist_map_t lru_model(pdf_t *rdist_pdf, int boundary);

#endif /* LRU_MODEL_H */
