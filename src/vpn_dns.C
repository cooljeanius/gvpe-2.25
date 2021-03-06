/* -*- C++ -*-
    vpn_dns.C -- handle the dns tunnel part of the protocol.
    Copyright (C) 2003-2011 Marc Lehmann <gvpe@schmorp.de>

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

// TODO: EDNS0 option to increase dns mtu?
// TODO: re-write dns packet parsing/creation using a safe mem-buffer
//       to ensure no buffer overflows or similar problems.

#include "config.h"

#if ENABLE_DNS

// dns processing is EXTREMELY ugly. For obvious(?) reasons.
// it's a hack, use only in emergency situations please.

#include <cstring>
#include <cassert>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <map>

#include <cstdio> /* bug in libgmp: gmp.h relies on cstdio being included */
#include <gmp.h>

#include "netcompat.h"

#include "vpn.h"

#define MIN_POLL_INTERVAL 0.025 // poll at most this often when no data received
#define MAX_POLL_INTERVAL 1.  // how often to poll minimally when the server has no data

#define INITIAL_TIMEOUT     0.1 // retry timeouts
#define INITIAL_SYN_TIMEOUT 2. // retry timeout for initial syn

#define MAX_SEND_INTERVAL 5. // optimistic?

#define MAX_WINDOW      1000 // max. for MAX_OUTSTANDING, and backlog
#define MAX_BACKLOG     (64*1024) // size of gvpe protocol backlog (bytes), must be > MAXSIZE

#define MAX_DOMAIN_SIZE 235 // 255 is legal limit, but bind doesn't compress well
// 240 leaves about 4 bytes of server reply data
// every request byte less give room for two reply bytes

#define SEQNO_MASK 0x3fff
#define SEQNO_EQ(a,b) ( 0 == ( ((a) ^ (b)) & SEQNO_MASK) )

#define MAX_LBL_SIZE 63
#define MAX_PKT_SIZE 512

#define RR_TYPE_A     1
#define RR_TYPE_NULL 10
#define RR_TYPE_TXT  16
#define RR_TYPE_AAAA 28
#define RR_TYPE_ANY 255

#define RR_CLASS_IN   1

#define CMD_IP_1   207
#define CMD_IP_2    46
#define CMD_IP_3   236

#define CMD_IP_RST  29 // some error, reset and retry
#define CMD_IP_REJ  32 // do not want you
#define CMD_IP_SYN 113 // connection established
#define CMD_IP_CSE 213 // connection established, but likely case mismatch

static bool
is_uc (char c)
{
  return 'A' <= c && c <= 'Z';
}

static bool
is_lc (char c)
{
  return 'a' <= c && c <= 'z';
}

// works for cmaps up to 255 (not 256!)
struct charmap
{
  enum { INVALID = (u8)255 };

  char encode [256]; // index => char
  u8 decode [256]; // char => index
  unsigned int size;

  charmap (const char *cmap);
};

charmap::charmap (const char *cmap)
{
  char *enc = encode;
  u8 *dec = decode;

  memset (enc, (char)      0, 256);
  memset (dec, (char)INVALID, 256);

  for (size = 0; cmap [size]; size++)
    {
      char c = cmap [size];

      enc [size] = c;
      dec [(u8)c] = size;

      // allow lowercase/uppercase aliases if possible
      if (is_uc (c) && dec [c + ('a' - 'A')] == INVALID) dec [c + ('a' - 'A')] = size;
      if (is_lc (c) && dec [c - ('a' - 'A')] == INVALID) dec [c - ('a' - 'A')] = size;
    }

  assert (size < 256);
}

#define MAX_DEC_LEN 500
#define MAX_ENC_LEN (MAX_DEC_LEN * 2)
#define MAX_LIMBS ((MAX_DEC_LEN * 8 + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS + 1)

// ugly. minimum base is 16(!)
struct basecoder
{
  charmap cmap;
  unsigned int enc_len [MAX_DEC_LEN];
  unsigned int dec_len [MAX_ENC_LEN];

  unsigned int encode_len (unsigned int len) const;
  unsigned int decode_len (unsigned int len) const;

  unsigned int encode (char *dst, u8 *src, unsigned int len) const;
  unsigned int decode (u8 *dst, char *src, unsigned int len) const;

  basecoder (const char *cmap);
};

basecoder::basecoder (const char *cmap)
: cmap (cmap)
{
  int decn = -1;

  for (unsigned int len = 0; len < MAX_DEC_LEN; ++len)
    {
      u8 src [MAX_DEC_LEN];
      u8 dst [MAX_ENC_LEN];

      memset (src, 255, len);

      mp_limb_t m [MAX_LIMBS];
      mp_size_t n;

      n = mpn_set_str (m, src, len, 256);
      n = mpn_get_str (dst, this->cmap.size, m, n);

      for (int i = 0; n && !dst [i]; ++i, --n)
        ;

      enc_len [len] = n;
      while (decn < n)
        dec_len [++decn] = len;
    }
}

unsigned int
basecoder::encode_len (unsigned int len) const
{
  return enc_len [len];
}

unsigned int
basecoder::decode_len (unsigned int len) const
{
  return dec_len [len];
}

unsigned int
basecoder::encode (char *dst, u8 *src, unsigned int len) const
{
  if (!len || len > MAX_DEC_LEN)
    return 0;

  int elen = encode_len (len);

  mp_limb_t m [MAX_LIMBS];
  mp_size_t n;

  u8 dst_ [MAX_ENC_LEN];

  n = mpn_set_str (m, src, len, 256);
  n = mpn_get_str (dst_, cmap.size, m, n);

  int plen = elen; // for padding

  while (n < plen)
    {
      *dst++ = cmap.encode [0];
      plen--;
    }

  for (unsigned int i = n - plen; i < n; ++i)
    *dst++ = cmap.encode [dst_ [i]];

  return elen;
}

unsigned int
basecoder::decode (u8 *dst, char *src, unsigned int len) const
{
  if (!len || len > MAX_ENC_LEN)
    return 0;

  u8 src_ [MAX_ENC_LEN];
  unsigned int elen = 0;

  while (len--)
    {
      u8 val = cmap.decode [(u8)*src++];

      if (val != charmap::INVALID)
        src_ [elen++] = val;
    }

  int dlen = decode_len (elen);

  mp_limb_t m [MAX_LIMBS];
  mp_size_t n;

  u8 dst_ [MAX_DEC_LEN];

  n = mpn_set_str (m, src_, elen, cmap.size);
  n = mpn_get_str (dst_, 256, m, n);

  if (n < dlen)
    {
      memset (dst, 0, dlen - n);
      memcpy (dst + dlen - n, dst_, n);
    }
  else
    memcpy (dst, dst_ + n - dlen, dlen);

  return dlen;
}

#if 0
struct test { test (); } test;

test::test ()
{
  basecoder cdc ("0123456789abcdefghijklmnopqrstuvwxyz");

  u8 in[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  static char enc[200];
  static u8 dec[200];

  for (int i = 1; i < 20; i++)
   {
     int elen = cdc.encode (enc, in, i);
     int dlen = cdc.decode (dec, enc, elen);

     printf ("%d>%d>%d (%s>%s)\n", i, elen, dlen, enc, dec);
   }
  abort ();
}
#endif

static basecoder cdc62 ("dDpPhHzZrR06QqMmjJkKBb34TtSsvVlL81xXaAeEFf92WwGgYyoO57UucCNniI"); // a-zA-Z0-9
static basecoder cdc36 ("dPhZr06QmJkB34tSvL81xAeF92wGyO57uCnI"); // a-z0-9 for case-changers
static basecoder cdc26 ("dPhZrQmJkBtSvLxAeFwGyOuCnI"); // a-z

/////////////////////////////////////////////////////////////////////////////

#define HDRSIZE 5

inline void
encode_header (char *data, int clientid, int seqno, int retry = 0)
{
  assert (clientid < 256);

  seqno &= SEQNO_MASK;

  u8 hdr[3] = {
    seqno,
    (seqno >> 8) | (retry << 6),
    clientid,
  };

  cdc36.encode (data, hdr, 3);
}

inline void
decode_header (char *data, int &clientid, int &seqno)
{
  u8 hdr[3];

  cdc36.decode (hdr, data, HDRSIZE);

  clientid = hdr[2];
  seqno = ((hdr[1] << 8) | hdr[0]) & SEQNO_MASK;
}

/////////////////////////////////////////////////////////////////////////////

struct byte_stream
{
  u8 *data;
  int maxsize;
  int fill;

  byte_stream (int maxsize);
  ~byte_stream ();

  bool empty () { return !fill; }
  int size () { return fill; }

  bool put (u8 *data, unsigned int datalen);
  bool put (vpn_packet *pkt);
  vpn_packet *get ();

  u8 *begin () { return data; }
  void remove (int count);
};

byte_stream::byte_stream (int maxsize)
: maxsize (maxsize), fill (0)
{
  data = new u8 [maxsize];
}

byte_stream::~byte_stream ()
{
  delete data;
}

void
byte_stream::remove (int count)
{
  assert (count <= fill);

  memmove (data, data + count, fill -= count);
}

bool
byte_stream::put (u8 *data, unsigned int datalen)
{
  if (maxsize - fill < datalen)
    return false;

  memcpy (this->data + fill, data, datalen); fill += datalen;

  return true;
}

bool
byte_stream::put (vpn_packet *pkt)
{
  if (maxsize - fill < pkt->len + 2)
    return false;

  data [fill++] = pkt->len >> 8;
  data [fill++] = pkt->len;

  memcpy (data + fill, pkt->at (0), pkt->len); fill += pkt->len;

  return true;
}

vpn_packet *
byte_stream::get ()
{
  unsigned int len;

  for (;;)
    {
      if (fill < 2)
        return 0;

      len = (data [0] << 8) | data [1];

      if (len <= MAXSIZE)
        break;

      // TODO: handle this better than skipping, e.g. by reset
      slog (L_DEBUG, _("DNS: corrupted packet (%02x %02x > %d) stream skipping a byte..."), data [0], data [1], MAXSIZE);
      remove (1);
    }

  if (fill < len + 2)
    return 0;

  vpn_packet *pkt = new vpn_packet;

  pkt->len = len;
  memcpy (pkt->at (0), data + 2, len);
  remove (len + 2);

  return pkt;
}

/////////////////////////////////////////////////////////////////////////////

#define FLAG_QUERY    ( 0 << 15)
#define FLAG_RESPONSE ( 1 << 15)
#define FLAG_OP_MASK  (15 << 11)
#define FLAG_OP_QUERY ( 0 << 11)
#define FLAG_AA       ( 1 << 10)
#define FLAG_TC       ( 1 <<  9)
#define FLAG_RD       ( 1 <<  8)
#define FLAG_RA       ( 1 <<  7)
#define FLAG_AUTH     ( 1 <<  5)
#define FLAG_RCODE_MASK     (15 << 0)
#define FLAG_RCODE_OK       ( 0 << 0)
#define FLAG_RCODE_FORMERR  ( 1 << 0)
#define FLAG_RCODE_SERVFAIL ( 2 << 0)
#define FLAG_RCODE_NXDOMAIN ( 3 << 0)
#define FLAG_RCODE_REFUSED  ( 5 << 0)

#define DEFAULT_CLIENT_FLAGS (FLAG_QUERY | FLAG_OP_QUERY | FLAG_RD)
#define DEFAULT_SERVER_FLAGS (FLAG_RESPONSE | FLAG_OP_QUERY | FLAG_AA | FLAG_RD | FLAG_RA)

struct dns_cfg
{
  static int next_uid;

  u8 chksum;
  u8 rrtype;
  u16 uid; // to make request unique

  u8 version;
  u8 flags;
  u16 max_size;

  u8 id1, id2, id3, id4;

  u16 client;
  u8 def_ttl;
  u8 r0;

  u8 syn_cdc; // cdc en/decoder for syn (A?) requests
  u8 hdr_cdc; // cdc en/decoder for regular request headers
  u8 req_cdc; // cdc en/decoder for regular (ANY?) request data
  u8 rep_cdc; // cdc en/decoder for regular (TXT) replies, 0 == 8 bit encoding

  u8 r1, r2, r3, r4;

  void reset (int clientid);
  bool valid ();
  u8 get_chksum ();
};

int dns_cfg::next_uid;

void
dns_cfg::reset (int clientid)
{
  // this ID must result in some mixed-case characters in cdc26-encoding
  id1 = 'G';
  id2 = 'V';
  id3 = 'P';
  id4 = 'E';

  version  = 2;

  rrtype   = RR_TYPE_TXT;
  flags    = 0;
  def_ttl  = 0;
  syn_cdc  = 26;
  hdr_cdc  = 36;
  req_cdc  = conf.dns_case_preserving ? 62 : 36;
  rep_cdc  = 0;
  max_size = htons (MAX_PKT_SIZE);
  client   = htons (clientid);
  uid      = ++next_uid;

  r0 = r1 = r2 = r3 = r4 = 0;

  chksum = get_chksum ();
}

// simple but not trivial chksum
u8
dns_cfg::get_chksum ()
{
  unsigned int sum = 0xff00; // only 16 bits required

  u8 old_chksum = chksum;
  chksum = 0;

  for (unsigned int i = 0; i < sizeof (*this); ++i)
    sum += ((u8 *)this)[i] * (i + 1);

  chksum = old_chksum;

  return sum + (sum >> 8);
}

bool
dns_cfg::valid ()
{
  // although the protocol itself allows for some configurability,
  // only the following encoding/decoding settings are implemented.
  return id1 == 'G'
      && id2 == 'V'
      && id3 == 'P'
      && id4 == 'E'
      && version == 2
      && syn_cdc == 26
      && hdr_cdc == 36
      && (req_cdc == 36 || req_cdc == 62)
      && rep_cdc == 0
      && chksum == get_chksum ();
}

struct dns_packet : net_packet
{
  u16 id;
  u16 flags; // QR:1 Opcode:4 AA:1 TC:1 RD:1 RA:1 Z:3 RCODE:4
  u16 qdcount, ancount, nscount, arcount;

  u8 data [MAXSIZE - 6 * 2];

  int decode_label (char *data, int size, int &offs);
};

int
dns_packet::decode_label (char *data, int size, int &offs)
{
  char *orig = data;

  memset (data, 0, size);

  while (offs < size - 1)
    {
      u8 len = (*this)[offs++];

      if (!len)
        break;
      else if (len < 64)
        {
          if (size < len + 1 || offs + len >= MAXSIZE - 1)
            break;

          memcpy (data, &((*this)[offs]), len);

          data += len; size -= len; offs += len;
          *data++ = '.'; size--;
        }
      else
        {
          int offs2 = ((len & 63) << 8) + (*this)[offs++];

          data += decode_label (data, size, offs2);
          break;
        }
    }

  return data - orig;
}

/////////////////////////////////////////////////////////////////////////////

static
u16 next_id ()
{
  static u16 dns_id = 0; // TODO: should be per-vpn

#if 1
  if (!dns_id)
    dns_id = time (0);

  // the simplest lsfr with periodicity 65535 i could find
  dns_id = (dns_id << 1)
           | (((dns_id >> 1)
               ^ (dns_id >> 2)
               ^ (dns_id >> 4)
               ^ (dns_id >> 15)) & 1);

  return dns_id;
#else
  dns_id++;//D

  return htons (dns_id);
#endif
}

struct dns_rcv;
struct dns_snd;

struct dns_connection
{
  connection *c;
  struct vpn *vpn;

  dns_cfg cfg;

  bool established;
  const basecoder *cdc;

  tstamp last_received;
  tstamp last_sent;
  double min_latency;
  double poll_interval, send_interval;

  vector<dns_rcv *> rcvpq;

  byte_stream rcvdq; int rcvseq; int repseq;
  byte_stream snddq; int sndseq;

  inline void time_cb (ev::timer &w, int revents); ev::timer tw;
  void receive_rep (dns_rcv *r);

  void reset (); // quite like tcp RST
  void set_cfg (); // to be called after any cfg changes

  dns_connection (connection *c);
  ~dns_connection ();
};

struct dns_snd
{
  dns_packet *pkt;
  tstamp timeout, sent;
  int retry;
  struct dns_connection *dns;
  int seqno;
  bool stdhdr;

  void gen_stream_req (int seqno, byte_stream &stream);
  void gen_syn_req ();

  dns_snd (dns_connection *dns);
  ~dns_snd ();
};

dns_snd::dns_snd (dns_connection *dns)
: dns (dns)
{
  timeout = 0;
  retry = 0;
  seqno = 0;
  sent = ev_now ();
  stdhdr = false;

  pkt = new dns_packet;

  pkt->id = next_id ();
}

dns_snd::~dns_snd ()
{
  delete pkt;
}

static void
append_domain (dns_packet &pkt, int &offs, const char *domain)
{
  // add tunnel domain
  for (;;)
    {
      const char *end = strchr (domain, '.');

      if (!end)
        end = domain + strlen (domain);

      int len = end - domain;

      pkt [offs++] = len;
      memcpy (pkt.at (offs), domain, len);
      offs += len;

      if (!*end)
        break;

      domain = end + 1;
    }
}

void
dns_snd::gen_stream_req (int seqno, byte_stream &stream)
{
  stdhdr = true;
  this->seqno = seqno;

  timeout = ev_now () + INITIAL_TIMEOUT;

  pkt->flags = htons (DEFAULT_CLIENT_FLAGS);
  pkt->qdcount = htons (1);

  int offs = 6*2;
  int dlen = MAX_DOMAIN_SIZE - (strlen (dns->c->conf->domain) + 2);
  // MAX_DOMAIN_SIZE is technically 255, but bind doesn't compress responses well,
  // so we need to have space for 2*MAX_DOMAIN_SIZE + header + extra

  char enc[256], *encp = enc;
  encode_header (enc, THISNODE->id, seqno);

  int datalen = dns->cdc->decode_len (dlen - (dlen + MAX_LBL_SIZE - 1) / MAX_LBL_SIZE - HDRSIZE);

  if (datalen > stream.size ())
    datalen = stream.size ();

  int enclen = dns->cdc->encode (enc + HDRSIZE, stream.begin (), datalen) + HDRSIZE;
  stream.remove (datalen);

  while (enclen)
    {
      int lbllen = enclen < MAX_LBL_SIZE ? enclen : MAX_LBL_SIZE;

      (*pkt)[offs++] = lbllen;
      memcpy (pkt->at (offs), encp, lbllen);

      offs += lbllen;
      encp += lbllen;

      enclen -= lbllen;
    }

  append_domain (*pkt, offs, dns->c->conf->domain);

  (*pkt)[offs++] = 0;
  (*pkt)[offs++] = RR_TYPE_ANY >> 8; (*pkt)[offs++] = RR_TYPE_ANY;
  (*pkt)[offs++] = RR_CLASS_IN >> 8; (*pkt)[offs++] = RR_CLASS_IN;

  pkt->len = offs;
}

void
dns_snd::gen_syn_req ()
{
  timeout = ev_now () + INITIAL_SYN_TIMEOUT;

  pkt->flags = htons (DEFAULT_CLIENT_FLAGS);
  pkt->qdcount = htons (1);

  int offs = 6 * 2;

  int elen = cdc26.encode ((char *)pkt->at (offs + 1), (u8 *)&dns->cfg, sizeof (dns_cfg));

  assert (elen <= MAX_LBL_SIZE);

  (*pkt)[offs] = elen;
  offs += elen + 1;
  append_domain (*pkt, offs, dns->c->conf->domain);

  (*pkt)[offs++] = 0;
  (*pkt)[offs++] = RR_TYPE_A   >> 8; (*pkt)[offs++] = RR_TYPE_A;
  (*pkt)[offs++] = RR_CLASS_IN >> 8; (*pkt)[offs++] = RR_CLASS_IN;

  pkt->len = offs;
}

struct dns_rcv
{
  int seqno;
  dns_packet *pkt; // reply packet
  u8 data [MAXSIZE]; // actually part of the reply packet...
  int datalen;

  dns_rcv (int seqno, u8 *data, int datalen);
  ~dns_rcv ();
};

dns_rcv::dns_rcv (int seqno, u8 *data, int datalen)
: seqno (seqno), pkt (new dns_packet), datalen (datalen)
{
  memcpy (this->data, data, datalen);
}

dns_rcv::~dns_rcv ()
{
  delete pkt;
}

/////////////////////////////////////////////////////////////////////////////

dns_connection::dns_connection (connection *c)
: c (c)
, rcvdq (MAX_BACKLOG * 2)
, snddq (MAX_BACKLOG)
{
  tw.set<dns_connection, &dns_connection::time_cb> (this);

  vpn = c->vpn;

  reset ();
}

dns_connection::~dns_connection ()
{
  reset ();
}

void
dns_connection::reset ()
{
  while (!rcvpq.empty ())
    {
      delete rcvpq.back ();
      rcvpq.pop_back ();
    }

  for (int i = vpn->dns_sndpq.size (); i--; )
    if (vpn->dns_sndpq [i]->dns == this)
      {
        vpn->dns_sndpq [i] = vpn->dns_sndpq.back ();
        vpn->dns_sndpq.pop_back ();
      }

  established = false;

  rcvseq = repseq = sndseq = 0;

  last_sent = 0;
  poll_interval = 0.5; // starting here
  send_interval = 0.5; // starting rate
  min_latency = INITIAL_TIMEOUT;
}

void
dns_connection::set_cfg ()
{
  cdc = cfg.req_cdc == 36 ? &cdc36 : &cdc62;
}

void
dns_connection::receive_rep (dns_rcv *r)
{
  if (r->datalen)
    poll_interval = max (poll_interval * (1. / 1.2), MIN_POLL_INTERVAL);
  else
    poll_interval = min (poll_interval * 1.1, MAX_POLL_INTERVAL);

  rcvpq.push_back (r);

  redo:

  // find next packet
  for (vector<dns_rcv *>::iterator i = rcvpq.end (); i-- != rcvpq.begin (); )
    if (SEQNO_EQ (rcvseq, (*i)->seqno))
      {
        //printf ("seqno eq %x %x\n", rcvseq, (*i)->seqno);//D
        // enter the packet into our input stream
        r = *i;

        // remove the oldest packet, look forward, as it's oldest first
        for (vector<dns_rcv *>::iterator j = rcvpq.begin (); j != rcvpq.end (); ++j)
          if (SEQNO_EQ ((*j)->seqno, rcvseq - MAX_WINDOW))
            {
              //printf ("seqno RR %x %x\n", (*j)->seqno, rcvseq - MAX_WINDOW);//D
              delete *j;
              rcvpq.erase (j);
              break;
            }

        rcvseq = (rcvseq + 1) & SEQNO_MASK;

        if (!rcvdq.put (r->data, r->datalen))
          {
            // MUST never overflow, can be caused by data corruption, TODO
            slog (L_CRIT, "DNS: !rcvdq.put (r->data, r->datalen)");
            reset ();
            return;
          }

        while (vpn_packet *pkt = rcvdq.get ())
          {
            sockinfo si;
            si.host = htonl (c->conf->id); si.port = 0; si.prot = PROT_DNSv4;

            vpn->recv_vpn_packet (pkt, si);
            delete pkt;
          }

        // check for further packets
        goto redo;
      }
}

void
vpn::dnsv4_server (dns_packet &pkt)
{
  u16 flags = ntohs (pkt.flags);

  int offs = 6 * 2; // skip header

  pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);

  if (0 == (flags & (FLAG_RESPONSE | FLAG_OP_MASK))
      && pkt.qdcount == htons (1))
    {
      char qname [MAXSIZE];
      int qlen = pkt.decode_label ((char *)qname, MAXSIZE - offs, offs);

      u16 qtype  = pkt [offs++] << 8; qtype  |= pkt [offs++];
      u16 qclass = pkt [offs++] << 8; qclass |= pkt [offs++];

      pkt.qdcount = htons (1);
      pkt.ancount = 0;
      pkt.nscount = 0; // should be self, as other nameservers reply like this
      pkt.arcount = 0; // a record for self, as other nameservers reply like this

      pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_SERVFAIL);

      int dlen = strlen (THISNODE->domain);

      if (qclass == RR_CLASS_IN
          && qlen > dlen + 1
          && !memcmp (qname + qlen - (dlen + 1), THISNODE->domain, dlen))
        {
          // now generate reply
          pkt.ancount = htons (1); // one answer RR
          pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_OK);

          if ((qtype == RR_TYPE_ANY
               || qtype == RR_TYPE_TXT
               || qtype == RR_TYPE_NULL)
              && qlen > dlen + 1 + HDRSIZE)
            {
              // correct class, domain: parse
              int client, seqno;
              decode_header (qname, client, seqno);

              if (0 < client && client <= conns.size ())
                {
                  connection *c = conns [client - 1];
                  dns_connection *dns = c->dns;
                  dns_rcv *rcv = NULL;

                  if (dns)
                    {
                      u8 data[MAXSIZE];
                      int datalen = dns->cdc->decode (data, qname + HDRSIZE, qlen - (dlen + 1 + HDRSIZE));

                      for (vector<dns_rcv *>::iterator i = dns->rcvpq.end (); i-- != dns->rcvpq.begin (); )
                        if (SEQNO_EQ ((*i)->seqno, seqno))
                          {
                            // already seen that request: simply reply with the cached reply
                            dns_rcv *r = *i;

                            slog (L_DEBUG, "DNS: duplicate packet received ID %d, SEQ %d", htons (r->pkt->id), seqno);

                            // refresh header & id, as the retry count could have changed
                            memcpy (r->pkt->at (6 * 2 + 1), pkt.at (6 * 2 + 1), HDRSIZE);
                            r->pkt->id = pkt.id;

                            memcpy (pkt.at (0), r->pkt->at (0), offs  = r->pkt->len);

                            goto duplicate_request;
                          }

                      // new packet, queue
                      rcv = new dns_rcv (seqno, data, datalen);
                      dns->receive_rep (rcv);
                    }

                  {
                    pkt [offs++] = 0xc0; pkt [offs++] = 6 * 2; // refer to name in query section

                    int rtype = dns ? dns->cfg.rrtype : RR_TYPE_A;
                    pkt [offs++] = rtype       >> 8; pkt [offs++] = rtype;       // type
                    pkt [offs++] = RR_CLASS_IN >> 8; pkt [offs++] = RR_CLASS_IN; // class
                    pkt [offs++] = 0; pkt [offs++] = 0;
                    pkt [offs++] = 0; pkt [offs++] = dns ? dns->cfg.def_ttl : 0; // TTL

                    int rdlen_offs = offs += 2;

                    if (dns)
                      {
                        int dlen = ntohs (dns->cfg.max_size) - offs;

                        // bind doesn't compress well, so reduce further by one label length
                        dlen -= qlen;

                        // only put data into in-order sequence packets, if
                        // we receive out-of-order packets we generate empty
                        // replies
                        //printf ("%d - %d & %x (=%d) < %d\n", seqno, dns->repseq, SEQNO_MASK, (seqno - dns->repseq) & SEQNO_MASK, MAX_WINDOW);//D
                        if (((seqno - dns->repseq) & SEQNO_MASK) <= MAX_WINDOW)
                          {
                            dns->repseq = seqno;

                            while (dlen > 1 && !dns->snddq.empty ())
                              {
                                int txtlen = dlen <= 255 ? dlen - 1 : 255;

                                if (txtlen > dns->snddq.size ())
                                  txtlen = dns->snddq.size ();

                                pkt[offs++] = txtlen;
                                memcpy (pkt.at (offs), dns->snddq.begin (), txtlen);
                                offs += txtlen;
                                dns->snddq.remove (txtlen);

                                dlen -= txtlen + 1;
                              }
                          }

                        // avoid completely empty TXT rdata
                        if (offs == rdlen_offs)
                          pkt[offs++] = 0;

                        slog (L_NOISE, "DNS: snddq %d", dns->snddq.size ());
                      }
                    else
                      {
                        // send RST
                        pkt [offs++] = CMD_IP_1; pkt [offs++] = CMD_IP_2; pkt [offs++] = CMD_IP_3;
                        pkt [offs++] = CMD_IP_RST;
                      }

                    int rdlen = offs - rdlen_offs;

                    pkt [rdlen_offs - 2] = rdlen >> 8;
                    pkt [rdlen_offs - 1] = rdlen;

                    if (dns)
                      {
                        // now update dns_rcv copy
                        rcv->pkt->len = offs;
                        memcpy (rcv->pkt->at (0), pkt.at (0), offs);
                      }
                  }

                  duplicate_request: ;
                }
              else
                pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);
            }
          else if (qtype == RR_TYPE_A
                   && qlen > dlen + 1 + cdc26.encode_len (sizeof (dns_cfg)))
            {
              dns_cfg cfg;
              cdc26.decode ((u8 *)&cfg, qname, cdc26.encode_len (sizeof (dns_cfg)));
              int client = ntohs (cfg.client);

              pkt [offs++] = 0xc0; pkt [offs++] = 6 * 2; // refer to name in query section

              pkt [offs++] = RR_TYPE_A   >> 8; pkt [offs++] = RR_TYPE_A;   // type
              pkt [offs++] = RR_CLASS_IN >> 8; pkt [offs++] = RR_CLASS_IN; // class
              pkt [offs++] = 0; pkt [offs++] = 0;
              pkt [offs++] = 0; pkt [offs++] = cfg.def_ttl; // TTL
              pkt [offs++] = 0; pkt [offs++] = 4; // rdlength

              pkt [offs++] = CMD_IP_1; pkt [offs++] = CMD_IP_2; pkt [offs++] = CMD_IP_3;
              pkt [offs++] = CMD_IP_REJ;

              if (0 < client && client <= conns.size ())
                {
                  connection *c = conns [client - 1];

                  if (cfg.valid ())
                    {
                      slog (L_INFO, _("DNS: client %d connects (version %d, req_cdc %d)"), client, cfg.version, cfg.req_cdc);

                      // check for any encoding mismatches - hints at a case problem
                      char qname2 [MAX_ENC_LEN];
                      cdc26.encode (qname2, (u8 *)&cfg, sizeof (dns_cfg));

                      delete c->dns;

                      pkt [offs - 1] = memcmp (qname, qname2, cdc26.encode_len (sizeof (dns_cfg)))
                                       ? CMD_IP_CSE : CMD_IP_SYN;

                      c->dns = new dns_connection (c);
                      c->dns->cfg = cfg;
                      c->dns->set_cfg ();
                    }
                }
            }
        }

      pkt.len = offs;
    }
}

void
vpn::dnsv4_client (dns_packet &pkt)
{
  u16 flags = ntohs (pkt.flags);
  int offs = 6 * 2; // skip header

  pkt.qdcount = ntohs (pkt.qdcount);
  pkt.ancount = ntohs (pkt.ancount);

  // go through our request list and find the corresponding request
  for (vector<dns_snd *>::iterator i = dns_sndpq.begin ();
       i != dns_sndpq.end ();
       ++i)
    if ((*i)->pkt->id == pkt.id)
      {
        dns_connection *dns = (*i)->dns;
        connection *c = dns->c;
        int seqno = (*i)->seqno;
        u8 data[MAXSIZE], *datap = data;
        //printf ("rcv pkt %x\n", seqno);//D

        if ((*i)->retry)
          {
            dns->send_interval *= 1.01;
            if (dns->send_interval > MAX_SEND_INTERVAL)
              dns->send_interval = MAX_SEND_INTERVAL;
          }
        else
          {
#if 0
            dns->send_interval *= 0.999;
#endif
            // the latency surely puts an upper bound on
            // the minimum send interval
            double latency = ev_now () - (*i)->sent;

            if (latency < dns->min_latency)
              dns->min_latency = latency;

            if (dns->send_interval > dns->min_latency * conf.dns_overlap_factor)
              dns->send_interval = dns->min_latency * conf.dns_overlap_factor;

            if (dns->send_interval < conf.dns_send_interval)
              dns->send_interval = conf.dns_send_interval;
          }

        delete *i;
        dns_sndpq.erase (i);

        if (flags & FLAG_RESPONSE && !(flags & FLAG_OP_MASK))
          {
            char qname[MAXSIZE];

            while (pkt.qdcount-- && offs < MAXSIZE - 4)
              {
                int qlen = pkt.decode_label ((char *)qname, MAXSIZE - offs, offs);
                offs += 4; // skip qtype, qclass
              }

            while (pkt.ancount-- && offs < MAXSIZE - 10 && datap)
              {
                int qlen = pkt.decode_label ((char *)qname, MAXSIZE - offs, offs);

                u16 qtype  = pkt [offs++] << 8; qtype  |= pkt [offs++];
                u16 qclass = pkt [offs++] << 8; qclass |= pkt [offs++];
                u32 ttl  = pkt [offs++] << 24;
                    ttl |= pkt [offs++] << 16;
                    ttl |= pkt [offs++] <<  8;
                    ttl |= pkt [offs++];
                u16 rdlen = pkt [offs++] << 8; rdlen |= pkt [offs++];

                if (qtype == RR_TYPE_NULL || qtype == RR_TYPE_TXT || qtype == dns->cfg.rrtype)
                  {
                    if (rdlen <= MAXSIZE - offs)
                      {
                        // decode bytes, finally

                        while (rdlen)
                          {
                            int txtlen = pkt [offs++];

                            assert (txtlen + offs < MAXSIZE - 1);

                            memcpy (datap, pkt.at (offs), txtlen);
                            datap += txtlen; offs += txtlen;

                            rdlen -= txtlen + 1;
                          }
                      }
                  }
                else if (qtype == RR_TYPE_A)
                  {
                    u8 ip [4];

                    ip [0] = pkt [offs++];
                    ip [1] = pkt [offs++];
                    ip [2] = pkt [offs++];
                    ip [3] = pkt [offs++];

                    if (ip [0] == CMD_IP_1
                        && ip [1] == CMD_IP_2
                        && ip [2] == CMD_IP_3)
                      {
                        slog (L_TRACE, _("DNS: got tunnel meta command %02x"), ip [3]);

                        if (ip [3] == CMD_IP_RST)
                          {
                            slog (L_DEBUG, _("DNS: got tunnel RST request."));

                            dns->reset ();
                            return;
                          }
                        else if (ip [3] == CMD_IP_SYN)
                          {
                            slog (L_DEBUG, _("DNS: got tunnel SYN reply, server likes us."));
                            dns->established = true;
                          }
                        else if (ip [3] == CMD_IP_CSE)
                          {
                            if (conf.dns_case_preserving)
                              {
                                slog (L_INFO, _("DNS: got tunnel CSE reply, globally downgrading to case-insensitive protocol."));
                                conf.dns_case_preserving = false;
                                dns->reset ();
                                return;
                              }
                            else
                              {
                                slog (L_DEBUG, _("DNS: got tunnel CSE reply, server likes us."));
                                dns->established = true;
                              }
                          }
                        else if (ip [3] == CMD_IP_REJ)
                          {
                            slog (L_ERR, _("DNS: got tunnel REJ reply, server does not like us."));
                            dns->tw.start (60.);
                          }
                        else
                          {
                            slog (L_INFO, _("DNS: got unknown meta command %02x"), ip [3]);
                            dns->tw.start (60.);
                          }
                      }
                    else
                      slog (L_INFO, _("DNS: got spurious a record %d.%d.%d.%d"),
                            ip [0], ip [1], ip [2], ip [3]);

                    return;
                  }

                int client, rseqno;
                decode_header (qname, client, rseqno);

                if (client != THISNODE->id)
                  {
                    slog (L_INFO, _("DNS: got dns tunnel response with wrong clientid, ignoring"));
                    datap = 0;
                  }
                else if (rseqno != seqno)
                  {
                    slog (L_DEBUG, _("DNS: got dns tunnel response with wrong seqno, badly caching nameserver?"));
                    datap = 0;
                  }
              }
          }

        // todo: pkt now used
        if (datap)
          dns->receive_rep (new dns_rcv (seqno, data, datap - data));

        break;
      }
}

void
vpn::dnsv4_ev (ev::io &w, int revents)
{
  if (revents & EV_READ)
    {
      dns_packet *pkt = new dns_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);

      pkt->len = recvfrom (w.fd, pkt->at (0), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      if (pkt->len > 0)
        {
          if (ntohs (pkt->flags) & FLAG_RESPONSE)
            dnsv4_client (*pkt);
          else
            {
              dnsv4_server (*pkt);
              sendto (w.fd, pkt->at (0), pkt->len, 0, (sockaddr *)&sa, sa_len);
            }

          delete pkt;
        }
    }
}

bool
vpn::send_dnsv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  int client = ntohl (si.host);

  assert (0 < client && client <= conns.size ());

  connection *c = conns [client - 1];

  if (!c->dns)
    c->dns = new dns_connection (c);

  if (c->dns->snddq.put (pkt))
    {
      min_it (c->dns->poll_interval, 0.25);
      c->dns->tw ();
    }

  // always return true even if the buffer overflows
  return true;
}

void
dns_connection::time_cb (ev::timer &w, int revents)
{
  // servers have to be polled
  if (THISNODE->dns_port)
    return;

  // check for timeouts and (re)transmit
  tstamp next = 86400 * 365;
  dns_snd *send = 0;

  for (vector<dns_snd *>::iterator i = vpn->dns_sndpq.begin ();
       i != vpn->dns_sndpq.end ();
       ++i)
    {
      dns_snd *r = *i;

      if (r->timeout <= ev_now ())
        {
          if (!send)
            {
              send = r;

              r->retry++;
              r->timeout = ev_now () + r->retry * min_latency * conf.dns_timeout_factor;
              //printf ("RETRY %x (%d, %f)\n", r->seqno, r->retry, r->timeout - ev_now ());//D

              // the following code changes the query section a bit, forcing
              // the forwarder to generate a new request
              if (r->stdhdr)
                encode_header ((char *)r->pkt->at (6 * 2 + 1), THISNODE->id, r->seqno, r->retry);
            }
        }
      else
        min_it (next, r->timeout - ev_now ());
    }

  if (!send)
    {
      // generate a new packet, if wise

      if (!established)
        {
          if (vpn->dns_sndpq.empty ())
            {
              send = new dns_snd (this);

              cfg.reset (THISNODE->id);
              set_cfg ();
              send->gen_syn_req ();
            }
        }
      else if (vpn->dns_sndpq.size () < conf.dns_max_outstanding
               && !SEQNO_EQ (rcvseq, sndseq - (MAX_WINDOW - 1)))
        {
          if (last_sent + send_interval <= ev_now ())
            {
              //printf ("sending data request etc.\n"); //D
              if (!snddq.empty ())
                min_it (next, send_interval);

              send = new dns_snd (this);
              send->gen_stream_req (sndseq, snddq);
              send->timeout = ev_now () + min_latency * conf.dns_timeout_factor;
              //printf ("SEND %x (%f)\n", send->seqno, send->timeout - ev_now (), min_latency, conf.dns_timeout_factor);//D

              sndseq = (sndseq + 1) & SEQNO_MASK;
            }
          else
            min_it (next, last_sent + send_interval - ev_now ());
        }

      if (send)
        vpn->dns_sndpq.push_back (send);
    }

  if (send)
    {
      last_sent = ev_now ();
      sendto (vpn->dnsv4_fd,
              send->pkt->at (0), send->pkt->len, 0,
              vpn->dns_forwarder.sav4 (), vpn->dns_forwarder.salenv4 ());
    }

  min_it (next, last_sent + max (poll_interval, send_interval) - ev_now ());

  slog (L_NOISE, "DNS: pi %f si %f N %f (%d:%d %d)",
        poll_interval, send_interval, next - ev_now (),
        vpn->dns_sndpq.size (), snddq.size (),
        rcvpq.size ());

  w.start (next);
}

#endif

