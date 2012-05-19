#include "lru_model.hh"

#include <stdio.h>

sdist_map_t
lru_model(rdist_hist_t &rdist_hist, int count, int boundary)
{
    pdf_t       rdist_pdf = HIST_NULL;
    sdist_map_t sdist_map;

    rdist_hist_t::iterator i = rdist_hist.begin();
    rdist_hist_t::iterator e = rdist_hist.end();
    for (; i != e; i++)
        HIST_APPEND(&rdist_pdf, i->first, (float)i->second / count);

    return lru_model(&rdist_pdf, boundary);
}

