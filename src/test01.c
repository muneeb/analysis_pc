#include <stdio.h>
#include <math.h>
#include "hist.h"
#include "lru_model.h"

#define TOL 0.00001

static int
map_compare(sdist_map_t *m1, sdist_map_t *m2)
{
    if (VECT_USED(m1) != VECT_USED(m2))
        return 1;

    for (int i = 0; i < VECT_USED(m1); i++) {
        float r1 = VECT_ELEM(m1, i).rdist;
        float s1 = VECT_ELEM(m1, i).sdist;
        float p1 = VECT_ELEM(m1, i).pdf;
        float r2 = VECT_ELEM(m2, i).rdist;
        float s2 = VECT_ELEM(m2, i).sdist;
        float p2 = VECT_ELEM(m2, i).pdf;

        if (fabs(r1 - r2) > TOL || fabs(s1 - s2) > TOL || fabs(p1 - p2) > TOL)
            return 1;
    }
    
    return 0;
}

static pdf_t
pdf_build(float *b, float *c, int size)
{
    pdf_t rdist_pdf = HIST_NULL;
    for (int i = 0; i < size; i++)
        HIST_APPEND(&rdist_pdf, b[i], c[i]);
    return rdist_pdf;
}

static sdist_map_t
map_build(float *rdist, float *sdist, float *pdf, int size)
{
    sdist_map_t sdist_map = SDIST_MAP_NULL;
    for (int i = 0; i < size; i++)
        SDIST_MAP_APPEND(&sdist_map, rdist[i], sdist[i], pdf[i], 0.0);
    return sdist_map;
}

static void
print_sdist_map(sdist_map_t *sdist_map)
{
    sdist_map_elem_t iter;
    SDIST_MAP_FOREACH(sdist_map, iter) {
        printf("rdist: %f, sdist: %f, pdf: %f\n",
               iter.rdist, iter.sdist, iter.pdf);
    }
}

static int
test(float *rdist, float *pdf, float *ref_sdist, int size)
{
    int ret = 0;

    pdf_t rdist_pdf = pdf_build(rdist, pdf, size);
    sdist_map_t ref_sdist_map  = map_build(rdist, ref_sdist, pdf, size);
    
    sdist_map_t sdist_map = lru_model(&rdist_pdf, 0);

    if (map_compare(&ref_sdist_map, &sdist_map)) {
        printf("ref\n");
        print_sdist_map(&ref_sdist_map);
        printf("mod\n");
        print_sdist_map(&sdist_map);
        ret = 1;
    }

    HIST_FINI(&rdist_pdf);
    SDIST_MAP_FINI(&ref_sdist_map);
    return ret;
}


int
main(int argc, char **argv)
{
    float test1_rdist[] = {1.0, 2.0, 3.0, 4.0, 5.0};
    float test1_pdf[]   = {0.2, 0.2, 0.2, 0.2, 0.2};
    float ref1_sdist[]  = {1.0, 1.8, 2.4, 2.8, 3.0};
    if (test(test1_rdist, test1_pdf, ref1_sdist, 5)) {
        fprintf(stderr, "test1 failed\n");
        return EXIT_FAILURE;
    }

    float test2_rdist[] = {0.0, 2.0, 4.0, 6.0, 8.0};
    float test2_pdf[]  = {0.2, 0.2, 0.2, 0.2, 0.2};
    float ref2_sdist[] = {0.0, 1.6, 2.8, 3.6, 4.0};
    if (test(test2_rdist, test2_pdf, ref2_sdist, 5)) {
        fprintf(stderr, "test2 failed\n");
        return EXIT_FAILURE;
    }

    float test3_rdist[] = {1.0, 3.0, 5.0, 7.0, 8.0};
    float test3_pdf[]   = {0.2, 0.2, 0.2, 0.2, 0.2};
    float ref3_sdist[]  = {1.0, 2.6, 3.8, 4.6, 4.8};
    if (test(test3_rdist, test3_pdf, ref3_sdist, 5)) {
        fprintf(stderr, "test3 failed\n");
        return EXIT_FAILURE;
    }

    return 0;
}
