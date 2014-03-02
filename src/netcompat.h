/*
    netcompat.h -- network compatibility header
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

#ifndef GVPE_NETCOMPAT_H
#define GVPE_NETCOMPAT_H

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#include <net/if.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif

#ifndef IPTOS_MINCOST
# define IPTOS_MINCOST      0x02
#endif
#ifndef IPTOS_RELIABILITY
# define IPTOS_RELIABILITY  0x04
#endif
#ifndef IPTOS_THROUGHPUT
# define IPTOS_THROUGHPUT   0x08
#endif
#ifndef IPTOS_LOWDELAY
# define IPTOS_LOWDELAY     0x10
#endif

#ifndef IPTOS_TOS_MASK
# define IPTOS_TOS_MASK (IPTOS_LOWDELAY | IPTOS_THROUGHPUT | IPTOS_RELIABILITY | IPTOS_MINCOST)
#endif

#if !defined(SOL_IP) && defined(IPPROTO_IP)
# define SOL_IP IPPROTO_IP
#endif

#ifndef IPPROTO_GRE
# define IPPROTO_GRE 47
#endif

#ifndef ICMP_ECHOREPLY
# define ICMP_ECHOREPLY 0
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#if ENABLE_ICMP
# include <netinet/ip_icmp.h>
struct icmp_header {
  u8          type;
  u8          code;
  u16         checksum;
  union {
        struct {
                u16   id;
                u16   sequence;
        } echo;
        u32   gateway;
        struct {
                u16   unused;
                u16   mtu;
        } frag;
  } un;
};
#endif

#endif

