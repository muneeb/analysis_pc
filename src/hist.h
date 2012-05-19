#ifndef HIST_H
#define HIST_H
#include <uart/vect.h>

typedef struct {
    float b;
    float c;
} bucket_t;

typedef VECT(bucket_t) hist_t;

#define HIST_NULL               VECT_NULL
#define HIST_INIT(hist)         VECT_INIT(hist)
#define HIST_FINI(hist)         VECT_FINI(hist)
#define HIST_FOREACH(h, i)      VECT_FOREACH(h, i)

#define HIST_APPEND(hist, _b, _c) do {  \
    bucket_t bucket;                    \
    bucket.b = _b;                      \
    bucket.c = _c;                      \
    VECT_APPEND(hist, bucket);          \
} while (0)

typedef hist_t pdf_t;
typedef hist_t cdf_t;
typedef hist_t rcdf_t;

pdf_t  hist_to_pdf(hist_t *hist);
cdf_t  pdf_to_cdf(pdf_t *pdf);
rcdf_t pdf_to_rcdf(pdf_t *pdf);
rcdf_t cdf_to_rcdf(cdf_t *cdf);

void hist_print(hist_t *hist);

#endif /* HIST_H */
