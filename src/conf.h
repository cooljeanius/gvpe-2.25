/*
    conf.h -- configuration database
    Copyright (C) 2003-2008 Marc Lehmann <gvpe@schmorp.de>

    This file is part of GVPE.

    GVPE is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
    Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, see <http://www.gnu.org/licenses/>.

    Additional permission under GNU GPL version 3 section 7

    If you modify this Program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a modified
    version of that library), containing parts covered by the terms of the
    OpenSSL or SSLeay licenses, the licensors of this Program grant you
    additional permission to convey the resulting work.  Corresponding
    Source for a non-source form of such a combination shall include the
    source code for the parts of OpenSSL used as well as that of the
    covered work.
*/

#ifndef GVPE_CONF_H__
#define GVPE_CONF_H__

#include <vector>

#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include <sys/types.h>
#include <unistd.h>
#ifdef __cplusplus
}/*;*/
#endif /* __cplusplus */

#include "slog.h"
#include "global.h"

#define DEFAULT_REKEY			3607	// interval between rekeys
#define DEFAULT_RESEED			3613	// interval between rng reseeds
#define DEFAULT_KEEPALIVE		60	// one keepalive/minute (it's just 8 bytes...)
#define DEFAULT_UDPPORT			655	// same as tinc, conflicts would be rare
#define DEFAULT_MTU			1500	// let's ether-net
#define DEFAULT_MAX_RETRY		3600	// retry at least this often
#define DEFAULT_MAX_TTL			60	// packets expire after this many seconds
#define DEFAULT_MAX_QUEUE		512	// never queue more than this many packets

#define DEFAULT_DNS_TIMEOUT_FACTOR	8.F	// initial retry timeout multiple
#define DEFAULT_DNS_SEND_INTERVAL	.01F	// minimum send interval
#define DEFAULT_DNS_OVERLAP_FACTOR	.5F	// RTT * LATENCY_FACTOR == sending rate
#define DEFAULT_DNS_MAX_OUTSTANDING	100	// max. number of outstanding requests

enum
{
  PROT_UDPv4  = 0x01, // udp over ipv4
  PROT_IPv4   = 0x02, // generic ip protocol
  PROT_TCPv4  = 0x04, // tcp over ipv4 (server)
  PROT_ICMPv4 = 0x08, // icmp over ipv4
  PROT_DNSv4  = 0x10, // dns tunnel ipv4 (server)
  PROT_ALL    = 0x1f
};

#define PROT_RELIABLE (PROT_TCPv4 | PROT_DNSv4)
#define PROT_SLOW     PROT_DNSv4

// select the "best" protocol of the available ones
u8 best_protocol (u8 protset);
const char *strprotocol (u8 protocol);

struct conf_node
{
  int id;         // the id of this node, a 12-bit-number

  RSA *rsa_key;   // his public key
  char *nodename; // nodename, an internal nickname.
  char *hostname; // hostname, if known, or NULL.
  char *if_up_data;
#if ENABLE_DNS
  char *domain;   // dns tunnel domain
#endif
  char *dns_hostname;
  u16 dns_port;

  u8 protocols;   // protocols this host can send & receive
  u16 udp_port, tcp_port;   // the port to bind to
  int max_retry;
  double max_ttl;   // packets expire after this many seconds
  int max_queue;    // maixmum send queue length

  enum connectmode { C_ONDEMAND, C_NEVER, C_ALWAYS, C_DISABLED } connectmode;
  bool compress;
  bool inherit_tos; // inherit TOS in packets send to this destination

  vector<const char *> allow_direct;
  vector<const char *> deny_direct;

  u32 routerprio;

  u8 connectable_protocols () const
  {
    u8 protocols = this->protocols;

    // mask out endpoints we can't connect to
    if (!udp_port) protocols &= ~PROT_UDPv4;
    if (!tcp_port) protocols &= ~PROT_TCPv4;
    if (!dns_port) protocols &= ~PROT_DNSv4;

    return protocols;
  }

  bool may_direct (struct conf_node *other);
  void finalise ();

  void print ();

  ~conf_node ();
};

struct configuration
{
  typedef vector<conf_node *> node_vector;
  node_vector nodes;
  conf_node default_node;
  conf_node *thisnode;
  char *seed_dev;   // the randomd evice to use for seeding
  double reseed;    // the interval between additional seeds
  int mtu;          // the mtu used for outgoing tunnel packets
  int nfmark;       // the SO_MARK // netfilter mark // fwmark
  double rekey;     // rekey interval
  double keepalive; // keepalive probes interval
  char *ifname;     // the interface name (tap0 ...)
  bool ifpersist;   // should the interface be persistent
  char *prikeyfile;
  RSA *rsa_key;     // our private rsa key
  loglevel llevel;
  u8 ip_proto;      // the ip protocol to use
  uid_t change_uid; // the uid of the user to switch to, or 0
  gid_t change_gid; // the gid of the user to switch to, or 0
  char *change_root;// the path to chroot to, "/" == anonymous
#if ENABLE_ICMP
  u8 icmp_type;     // the icmp type for the icmp-protocol
#endif

  char *script_if_up;
  char *script_node_up;
  char *script_node_change;
  char *script_node_down;
  char *pidfilename;

#if ENABLE_HTTP_PROXY
  char *proxy_auth;	// login:password
  char *proxy_host;	// the proxy hostname, e.g. proxy1.example.net
  u16 proxy_port;	// the proxy port, e.g. 3128
#endif

#if ENABLE_DNS
  char *dns_forw_host;
  bool dns_case_preserving;
  u16 dns_forw_port;
  float dns_timeout_factor;
  float dns_send_interval;
  float dns_overlap_factor;
  int dns_max_outstanding;
#endif

  void init ();
  void cleanup ();
  void clear ();

  // create a filename from string, replacing %s by the nodename
  // and using relative paths under confbase.
  char *config_filename (const char *name, const char *dflt = 0);

  void print ();

  configuration ();
  ~configuration ();
};

struct configuration_parser
{
  configuration &conf;

  bool need_keys;
  conf_node *node;

  int argc;
  char **argv;

  configuration_parser (configuration &conf, bool need_keys, int argc, char **argv);

  void parse_file (const char *fname);
  const char *parse_line (char *line);
  void parse_argv ();
};

extern struct configuration conf;

#define THISNODE ::conf.thisnode

#endif

