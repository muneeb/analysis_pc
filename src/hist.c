#include <stdio.h>
#include "lru_model.h"

static float
hist_sum(hist_t *hist)
{
    float sum = 0;

    bucket_t iter;
    HIST_FOREACH(hist, iter) {
        float count = iter.c;

        sum += count;
    }
    return sum;
}

pdf_t
hist_to_pdf(hist_t *hist)
{
    pdf_t pdf = HIST_NULL;
    float sum = hist_sum(hist);
    
    bucket_t iter;
    HIST_FOREACH(hist, iter) {
        float rdist = iter.b;
        float count = iter.c;

        HIST_APPEND(&pdf, rdist, count / sum);
    }

    return pdf;
}

cdf_t
pdf_to_cdf(pdf_t *pdf)
{
    cdf_t cdf = HIST_NULL;
    float sum = 0;
    
    bucket_t iter;
    HIST_FOREACH(pdf, iter) {
        float rdist = iter.b;
        float pdf = iter.c;

        HIST_APPEND(&cdf, rdist, sum);
        sum += pdf;
    }

    return cdf;
}

rcdf_t
pdf_to_rcdf(pdf_t *pdf)
{
    rcdf_t rcdf;
    cdf_t  cdf;

    cdf  = pdf_to_cdf(pdf);
    rcdf = cdf_to_rcdf(&cdf);

    HIST_FINI(&cdf);
    return rcdf;
}

rcdf_t
cdf_to_rcdf(cdf_t *cdf)
{
    rcdf_t rcdf = HIST_NULL;

    bucket_t iter;
    HIST_FOREACH(cdf, iter) {
        float rdist = iter.b;
        float cdf = iter.c;

        HIST_APPEND(&rcdf, rdist, 1.0 - cdf);
    }

    return rcdf;
}

void
hist_print(hist_t *hist)
{
    bucket_t iter;
    HIST_FOREACH(hist, iter) {
        float rdist = iter.b;
        float cdf = iter.c;

        printf("b: %f, c: %f\n", rdist, cdf);
    }
}


