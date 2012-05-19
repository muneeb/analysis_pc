#include <iostream>
#include <map>
using namespace std;
#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>
#include <uart/usf.h>
#include "lru_model.hh"

#define USF_E(_e)                                       \
    if ((_e) != USF_ERROR_OK) {                         \
        print_and_exit("%s\n", usf_strerror(error));    \
    }

#define RDIST_DANGLING ((uint64_t)-1)

static const char *usage_str = "";

static void
_print_and_exit(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

#define print_and_exit(fmt, args...) \
    _print_and_exit("%s:%d: " fmt, __FILE__, __LINE__, ##args)

class args_t {
public:
    args_t()
    : file_name(NULL),
      verbose(false),
      print_rdist(false),
      print_sdist(false),
      print_pdf(false),
      print_mratio(false) { }

    void parse(int argc, char **argv)
    {
        int c;

        while ((c = getopt(argc, argv, "vrspm")) != -1) {
            switch (c) {
                case 'v':
                    verbose = true;
                    break;
                case 'r':
                    print_rdist = true;
                    break;
                case 's':
                    print_sdist = true;
                    break;
                case 'p':
                    print_pdf = true;
                    break;
                case 'm':
                    print_mratio = true;
                    break;
            }
        }
        if (optind > argc)
            print_and_exit("%s\n", usage_str);

        file_name = argv[optind];
        
    }

public:
    char *file_name;

    bool verbose;
    bool print_rdist;
    bool print_sdist;
    bool print_pdf;
    bool print_mratio;
};


static void
sdist_map_print(sdist_map_t &sdist_map, args_t &args)
{
#define PRINT(_name) do {               \
    if (args.print_##_name) {           \
        if (args.verbose)               \
            cout << #_name << ": ";     \
        cout << iter._name << " ";      \
    }                                   \
} while (0)

    sdist_map_elem_t iter;
    SDIST_MAP_FOREACH(&sdist_map, iter) {
        if (iter.rdist >= RDIST_DANGLING)
            break;

        PRINT(rdist);
        PRINT(sdist);
        PRINT(pdf);
        PRINT(mratio);
        cout << endl;
    }
}

int
main(int argc, char **argv)
{
    args_t args;
    usf_file_t *usf_file;
    usf_header_t *header;
    usf_event_t event;
    usf_error_t error;

    args.parse(argc, argv);

    error = usf_open(&usf_file, args.file_name);
    USF_E(error);

    error = usf_header((const usf_header_t **)&header, usf_file);
    USF_E(error);

    if (header->flags & USF_FLAG_TRACE)
        print_and_exit("%s is not a trace file.\n", args.file_name);

    do {
        int count = 0;
        rdist_hist_t rdist_hist;
        sdist_map_t sdist_map;
            
        error = usf_read(usf_file, &event);
        USF_E(error);
        if (event.type != USF_EVENT_BURST)
            print_and_exit("File format error.\n");

        do {
            uint64_t rdist;

            error = usf_read(usf_file, &event);
            if (error == USF_ERROR_EOF)
                break;
            USF_E(error);

            count++;
            if (event.type == USF_EVENT_SAMPLE)
                rdist = event.u.sample.end.time - event.u.sample.begin.time - 1;
            else
                rdist = RDIST_DANGLING;

            if (rdist_hist.find(rdist) == rdist_hist.end())
                rdist_hist[rdist] = 1;
            else
                rdist_hist[rdist]++;
        } while (event.type != USF_EVENT_BURST);

        sdist_map = lru_model(rdist_hist, count, 1);
        sdist_map_print(sdist_map, args);
        SDIST_MAP_FINI(&sdist_map);

        if (error == USF_ERROR_EOF)
            break;
    } while (1);

    return 0;
}
