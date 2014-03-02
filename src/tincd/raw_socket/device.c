/*
    device.c -- raw socket
    Copyright (C) 2002-2004 Ivo Timmermans <ivo@tinc-vpn.org>,
                  2002-2004 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: device.c,v 1.2 2005-03-17 23:59:38 pcg Exp $
*/

#include <netpacket/packet.h>
#include <netinet/ether.h>

int device_fd = -1;
char *device;
char *iface;
char ifrname[IFNAMSIZ];
char *device_info;

static int device_total_in = 0;
static int device_total_out = 0;

bool setup_device(void)
{
	struct ifreq ifr;
	struct sockaddr_ll sa;

	cp();

	if(!get_config_string
		  (lookup_config(config_tree, "Interface"), &iface))
		iface = "eth0";

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = iface;

	device_info = _("raw socket");

	if((device_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		logger(LOG_ERR, _("Could not open %s: %s"), device_info,
			   strerror(errno));
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	if(ioctl(device_fd, SIOCGIFINDEX, &ifr)) {
		close(device_fd);
		logger(LOG_ERR, _("Can't find interface %s: %s"), iface,
			   strerror(errno));
		return false;
	}

	memset(&sa, '0', sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if(bind(device_fd, (struct sockaddr *) &sa, (socklen_t) sizeof(sa))) {
		logger(LOG_ERR, _("Could not bind %s to %s: %s"), device, iface, strerror(errno));
		return false;
	}

	logger(LOG_INFO, _("%s is a %s"), device, device_info);

	return true;
}

void close_device(void)
{
	cp();

	close(device_fd);
}

bool read_packet(vpn_packet_t *packet)
{
	int lenin;

	cp();

	if((lenin = read(device_fd, packet->data, MTU)) <= 0) {
		logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			   device, strerror(errno));
		return false;
	}

	packet->len = lenin;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
			   device_info);

	return true;
}

bool write_packet(vpn_packet_t *packet)
{
	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(write(device_fd, packet->data, packet->len) < 0) {
		logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
			   strerror(errno));
		return false;
	}

	device_total_out += packet->len;

	return true;
}

void dump_device_stats(void)
{
	cp();

	logger(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
	logger(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
	logger(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
}
