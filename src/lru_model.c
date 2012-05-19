#include <assert.h>
#include "lru_model.h"
#include "hist.h"

sdist_map_t
lru_model(pdf_t *rdist_pdf, int boundary)
{
    sdist_map_t sdist_map = SDIST_MAP_NULL;
    rcdf_t rdist_rcdf;
    float prev_rdist;
    float prev_sdist;
    float prev_pdf;
    float prev_mratio;

    assert(VECT_USED(rdist_pdf) > 0);

    rdist_rcdf = pdf_to_rcdf(rdist_pdf);

    prev_rdist  = VECT_ELEM(rdist_pdf, 0).b;
    prev_sdist  = prev_rdist;
    prev_pdf    = VECT_ELEM(rdist_pdf, 0).c;
    prev_mratio = 1.0 - prev_pdf; 
    SDIST_MAP_APPEND(&sdist_map, prev_rdist, prev_sdist, prev_pdf, prev_mratio);

    for (int i = 1; i < VECT_USED(rdist_pdf); i++) {
        float rdist = VECT_ELEM(rdist_pdf, i).b;
        float pdf   = VECT_ELEM(rdist_pdf, i).c;
        float rcdf  = VECT_ELEM(&rdist_rcdf, i).c;
        float sdist = prev_sdist;

        if (boundary)
            sdist += rcdf * (rdist - prev_rdist - 1) + rcdf / (1.0 - prev_pdf);
        else
            sdist += rcdf * (rdist - prev_rdist);

        SDIST_MAP_APPEND(&sdist_map, rdist, sdist, pdf, prev_mratio - pdf);
        prev_rdist   = rdist;
        prev_sdist   = sdist;
        prev_pdf     = pdf;
        prev_mratio -= pdf; 
    }

    HIST_FINI(&rdist_rcdf);
    return sdist_map;
}

