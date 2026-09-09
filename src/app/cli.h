/*
 * cli.h - Command-line interface definitions and configuration.
 *
 * Defines default configuration constants, parameter validation bounds,
 * and the traceroute_config_t structure used to encapsulate CLI options.
 */

#ifndef CLI_H
#define CLI_H

#define DEFAULT_FIRST_TTL    1
#define DEFAULT_MAX_TTL      64
#define DEFAULT_NQUERIES     3
#define DEFAULT_WAITTIME_S   3
#define DEFAULT_SENDWAIT_MS  100
#define DEFAULT_NUMERIC      0

#define MIN_TTL              1
#define MAX_TTL              255
#define MIN_QUERIES          1
#define MAX_QUERIES          10
#define MIN_WAITTIME_S       1
#define MAX_WAITTIME_S       60
#define MIN_SENDWAIT_MS      0
#define MAX_SENDWAIT_MS      10000

#define CLI_DECIMAL_BASE     10
#define CLI_NUMERIC_ON       1
#define REQUIRED_HOST_ARGS   1
#define CLI_OPTIND_INITIAL   1
#define CLI_PARSE_SUCCESS    0
#define CLI_PARSE_ERROR      (-1)

typedef struct {
    int first_ttl;      /* First hop TTL (default: 1, range: 1..255) */
    int max_ttl;        /* Maximum hops (default: 64, range: 1..255) */
    int nqueries;       /* Number of probes per hop (default: 3, range: 1..10) */
    int waittime_s;     /* Reply timeout in seconds (default: 3, range: 1..60) */
    int sendwait_ms;    /* Inter-probe delay in ms (default: 100, range: 0..10000) */
    int numeric;        /* Numeric output flag (default: 0) */
    const char *host;   /* Destination hostname or IPv4 string */
} traceroute_config_t;

/* Prints usage instructions to stderr */
void cli_usage(void);

/* Parses command line arguments into cfg. Returns 0 on success, -1 on error. */
int cli_parse(int argc, char **argv, traceroute_config_t *cfg);

#endif /* CLI_H */
