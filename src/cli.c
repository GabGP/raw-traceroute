/*
 * cli.c - Command-line parsing and argument validation.
 *
 * Implements getopt-based argument parsing, numeric range validation,
 * usage diagnostics, and relational boundary checks for traceroute.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

void cli_usage(void)
{
    fprintf(stderr,
            "usage: traceroute [-n] [-f first_ttl] [-m max_ttl] [-q nqueries]"
            " [-w waittime_s] [-z sendwait_ms] host\n");
}

static int parse_int_arg(const char *arg, int min, int max, const char *name,
                         int *out)
{
    char *end;
    long value;

    errno = 0;
    value = strtol(arg, &end, CLI_DECIMAL_BASE);
    if (*arg == '\0' || *end != '\0' || errno != 0 || value < min || value > max) {
        fprintf(stderr, "traceroute: invalid value for %s: \"%s\" (expected %d..%d)\n",
                name, arg, min, max);
        return -1;
    }
    *out = (int)value;
    return 0;
}

int cli_parse(int argc, char **argv, traceroute_config_t *cfg)
{
    int opt;

    optind = 1;
    cfg->first_ttl   = DEFAULT_FIRST_TTL;
    cfg->max_ttl     = DEFAULT_MAX_TTL;
    cfg->nqueries    = DEFAULT_NQUERIES;
    cfg->waittime_s  = DEFAULT_WAITTIME_S;
    cfg->sendwait_ms = DEFAULT_SENDWAIT_MS;
    cfg->numeric     = DEFAULT_NUMERIC;
    cfg->host        = NULL;

    while ((opt = getopt(argc, argv, "nf:m:q:w:z:")) != -1) {
        switch (opt) {
        case 'n':
            cfg->numeric = 1;
            break;
        case 'f':
            if (parse_int_arg(optarg, MIN_TTL, MAX_TTL, "-f", &cfg->first_ttl) < 0) return -1;
            break;
        case 'm':
            if (parse_int_arg(optarg, MIN_TTL, MAX_TTL, "-m", &cfg->max_ttl) < 0) return -1;
            break;
        case 'q':
            if (parse_int_arg(optarg, MIN_QUERIES, MAX_QUERIES, "-q", &cfg->nqueries) < 0) return -1;
            break;
        case 'w':
            if (parse_int_arg(optarg, MIN_WAITTIME_S, MAX_WAITTIME_S, "-w", &cfg->waittime_s) < 0) return -1;
            break;
        case 'z':
            if (parse_int_arg(optarg, MIN_SENDWAIT_MS, MAX_SENDWAIT_MS, "-z", &cfg->sendwait_ms) < 0) return -1;
            break;
        default:
            cli_usage();
            return -1;
        }
    }

    if (optind != argc - 1) {
        cli_usage();
        return -1;
    }
    cfg->host = argv[optind];

    if (cfg->first_ttl > cfg->max_ttl) {
        fprintf(stderr,
                "traceroute: first ttl (%d) may not be greater than max ttl (%d)\n",
                cfg->first_ttl, cfg->max_ttl);
        cli_usage();
        return -1;
    }

    return 0;
}
