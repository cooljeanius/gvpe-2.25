/* -*- C++ -*-
 *  gvpectrl.C -- the main file for gvpectrl
 *  Copyright (C) 1998-2002 Ivo Timmermans <ivo@o2w.nl>
 *                2000-2002 Guus Sliepen <guus@sliepen.eu.org>
 *                2003-2013 Marc Lehmann <gvpe@schmorp.de>
 *
 *	This file is part of GVPE.
 *
 *  GVPE is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 3 of the License, or (at your
 *  option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 *  Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *  Additional permission under GNU GPL version 3 section 7
 *
 *  If you modify this Program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a modified
 *  version of that library), containing parts covered by the terms of the
 *  OpenSSL or SSLeay licenses, the licensors of this Program grant you
 *  additional permission to convey the resulting work.  Corresponding
 *  Source for a non-source form of such a combination shall include the
 *  source code for the parts of OpenSSL used as well as that of the
 *  covered work.
 */

#include "config.h"

#ifdef __cplusplus
# include <cstdio>
# include <cstring>
# include <cstdlib>
# if !defined(asprintf) || defined(HAVE_STDIO_H)
#  include <stdio.h>
# endif /* !asprintf || HAVE_STDIO_H */
# if !defined(asprintf) || defined(HAVE_STDARG_H)
#  include <stdarg.h>
# endif /* !asprintf || HAVE_STDARG_H */
#else
# include <stdarg.h>
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
#endif /* __cplusplus */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "pidfile.h"

#include "conf.h"
#include "slog.h"
#include "util.h"
#include "vpn.h"

/* If nonzero, display usage information and exit. */
static int show_help;

/* If nonzero, print the version on standard output and exit.  */
static int show_version;

/* If nonzero, it will attempt to kill a running gvpe and exit. */
static int kill_gvpe;

/* If nonzero, it will attempt to kill a running gvpe and exit. */
static int show_config;

/* If nonzero, do not output anything but warnings/errors/very unusual conditions */
static int quiet;

/* If nonzero, generate public/private keypair for this net. */
static int generate_keys;

static struct option const long_options[] =
{
    {"config", required_argument, NULL, 'c'},
    {"kill", optional_argument, NULL, 'k'},
    {"help", no_argument, &show_help, 1},
    {"version", no_argument, &show_version, 1},
    {"generate-keys", no_argument, NULL, 'g'},
    {"quiet", no_argument, &quiet, 1},
    {"show-config", no_argument, &show_config, 's'},
    {NULL, 0, NULL, 0}
};

/* */
static void
usage (int status)
{
    if (status != 0)
        fprintf(stderr, _("Try `%s --help\' for more information.\n"),
                get_identity ());
    else
    {
        printf(_("Usage: %s [option]...\n\n"), get_identity ());
        printf(_("  -c, --config=DIR    Read configuration options from DIR.\n"
                 "  -k, --kill[=SIGNAL] Attempt to kill a running gvpe and exit.\n"
                 "  -g, --generate-keys Generate public/private RSA keypair.\n"
                 "  -s, --show-config   Display the configuration information.\n"
                 "  -q, --quiet         Be quite quiet.\n"
                 "      --help          Display this help and exit.\n"
                 "      --version       Output version information and exit.\n\n"));
        printf(_("Report bugs to <gvpe@schmorp.de>.\n"));
    }

    exit(status);
}

/* */
static void
parse_options(int argc, char **argv, char **envp)
{
    int r;
    int option_index = 0;

    while ((r = getopt_long(argc, argv, "c:k::qgs", long_options, &option_index)) != EOF)
    {
        switch (r)
        {
            case 0:		/* long option */
                break;

            case 'c':		/* config file */
                confbase = strdup(optarg);
                break;

            case 'k':		/* kill old gvpes */
                if (optarg)
                {
                    if (!strcasecmp(optarg, "HUP"))
                        kill_gvpe = SIGHUP;
                    else if (!strcasecmp(optarg, "TERM"))
                        kill_gvpe = SIGTERM;
                    else if (!strcasecmp(optarg, "KILL"))
                        kill_gvpe = SIGKILL;
                    else if (!strcasecmp(optarg, "USR1"))
                        kill_gvpe = SIGUSR1;
                    else if (!strcasecmp(optarg, "USR2"))
                        kill_gvpe = SIGUSR2;
                    else if (!strcasecmp(optarg, "INT"))
                        kill_gvpe = SIGINT;
                    else if (!strcasecmp(optarg, "ALRM"))
                        kill_gvpe = SIGALRM;
                    else
                    {
                        kill_gvpe = atoi(optarg);

                        if (!kill_gvpe)
                        {
                            fprintf(stderr,
                                    _("Invalid argument `%s'; SIGNAL must be a number or one of HUP, TERM, KILL, USR1, USR2, WINCH, INT or ALRM.\n"),
                                    optarg);
                            usage(1);
                        }
                    }
                }
                else
                    kill_gvpe = SIGTERM;

                break;

            case 'g':		/* generate public/private keypair */
                generate_keys = 2048; // Updated to use a secure key size
                break;

            case 's':
                show_config = 1;
                break;

            case 'q':
                quiet = 1;
                break;

            case '?':
                usage (1);

            default:
                break;
        }
    }
}

/* this function prettyprints the key generation process */
static int
indicator(int a, int b, BN_GENCB *cb)
{
    if (quiet) {
        return 1;
    }

    switch (a) {
        case 0:
            fprintf(stderr, ".");
            break;

        case 1:
            fprintf(stderr, "+");
            break;

        case 2:
            fprintf(stderr, "-");
            break;

        case 3:
            switch (b)
            {
                case 0:
                    fprintf(stderr, " p\n");
                    break;

                case 1:
                    fprintf(stderr, " q\n");
                    break;

                default:
                    fprintf(stderr, "?");
            }
            break;

        default:
            fprintf(stderr, "?");
    }

    return 1;
}

/*
 * generate public/private RSA keypairs for all hosts that do NOT have one.
 */
static int
keygen(int bits)
{
    FILE *f;
    char *name = NULL;
    char *fname;

    if (!asprintf(&fname, "%s/hostkeys", confbase)) {
        perror(fname);
        exit(EXIT_FAILURE);
    }
    mkdir(fname, 0700);
    free(fname);

    if (!asprintf(&fname, "%s/pubkey", confbase)) {
        perror(fname);
        exit(EXIT_FAILURE);
    }
    mkdir(fname, 0700);
    free(fname);

    for (configuration::node_vector::iterator i = conf.nodes.begin();
         i != conf.nodes.end(); ++i)
    {
        conf_node *node = *i;

        if (!asprintf(&fname, "%s/pubkey/%s", confbase, node->nodename)) {
            perror(fname);
            exit(EXIT_FAILURE);
        }

        f = fopen(fname, "a");

        /* some libcs are buggy and require an extra seek to the end: */
        if (!f || fseek(f, 0, SEEK_END)) {
            perror(fname);
            exit(EXIT_FAILURE);
        }

        if (ftell (f)) {
            if (!quiet) {
                fprintf(stderr, "'%s' already exists, skipping this node %d\n",
                        fname, quiet);
            }

            fclose(f);
            continue;
        }

        fprintf(stderr, _("generating %d bits key for %s:\n"), bits,
                node->nodename);

        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_bit(e, 0); BN_set_bit(e, 16); /* 0x10001, 65537 */
        BN_GENCB *cb;
        cb = BN_GENCB_new();
        if (!cb) {
            fprintf(stderr, _("failed to create a callback!"));
            exit(EXIT_FAILURE);
        }
        BN_GENCB_set(cb, indicator, 0);

        require(RSA_generate_key_ex(rsa, bits, e, cb));

        fprintf(stderr, _("Done.\n"));

        require(PEM_write_RSAPublicKey(f, rsa));
        fclose(f);
        free(fname);

        if (!asprintf(&fname, "%s/hostkeys/%s", confbase, node->nodename)) {
            perror(fname);
            exit(EXIT_FAILURE);
        }

        f = fopen(fname, "a");
        if (!f) {
            perror(fname);
            exit(EXIT_FAILURE);
        }

        require(PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL));
        fclose(f);
        free(fname);

        BN_free(e);
        RSA_free(rsa);
        BN_GENCB_free(cb);
    }

    return 0;
}

/* */
int
main(int argc, char **argv, char **envp)
{
    set_identity(argv[0]);
    log_to(LOGTO_STDERR);

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);

    parse_options(argc, argv, envp);

    if (show_version) {
        printf(_("%s version %s (built %s %s, protocol version %d.%d)\n"),
               get_identity(), VERSION, __DATE__, __TIME__, PROTOCOL_MAJOR,
               PROTOCOL_MINOR);
        printf(_("Built with kernel interface %s/%s.\n"), IFTYPE, IFSUBTYPE);
        printf(_("Copyright (C) 2003-2013 Marc Lehmann <gvpe@schmorp.de> & others.\n"
                 "See the AUTHORS file for a complete list.\n\n"
                 "gvpe comes with ABSOLUTELY NO WARRANTY. This is free software,\n"
                 "& you are welcome to redistribute it under certain conditions;\n"
                 "see the file COPYING for details.\n"));

        return 0;
    }

    if (show_help) {
        usage (0);
    }

    {
        configuration_parser(conf, false, 0, 0);
    }

    if (generate_keys) {
        RAND_load_file(conf.seed_dev, SEED_SIZE);
        exit(keygen(generate_keys));
    }

    if (kill_gvpe) {
        exit(kill_other(kill_gvpe));
    }

    if (show_config) {
        conf.print();
        exit(EXIT_SUCCESS);
    }

    usage(1);
}

/* EOF */
