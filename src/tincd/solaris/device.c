/*
    device.c -- Interaction with Solaris tun device
    Copyright (C) 2001-2004 Ivo Timmermans <ivo@tinc-vpn.org>,
                  2001-2004 Guus Sliepen <guus@tinc-vpn.org>

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


#include "system.h"

#include <sys/stropts.h>
#include <sys/sockio.h>
#include <net/if_tun.h>

#define DEFAULT_DEVICE "/dev/tun"

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
char *device_info = NULL;

static int device_total_in = 0;
static int device_total_out = 0;

bool setup_device(void)
{
	int ip_fd = -1, if_fd = -1;
	int ppa;
	char *ptr;

	cp();

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = DEFAULT_DEVICE;

	if((device_fd = open(device, O_RDWR | O_NONBLOCK)) < 0) {
		logger(LOG_ERR, _("Could not open %s: %s"), device, strerror(errno));
		return false;
	}

	ppa = 0;

	ptr = device;
	while(*ptr && !isdigit((int) *ptr))
		ptr++;
	ppa = atoi(ptr);

	if((ip_fd = open("/dev/ip", O_RDWR, 0)) < 0) {
		logger(LOG_ERR, _("Could not open /dev/ip: %s"), strerror(errno));
		return false;
	}

	/* Assign a new PPA and get its unit number. */
	if((ppa = ioctl(device_fd, TUNNEWPPA, ppa)) < 0) {
		logger(LOG_ERR, _("Can't assign new interface: %s"), strerror(errno));
		return false;
	}

	if((if_fd = open(device, O_RDWR, 0)) < 0) {
		logger(LOG_ERR, _("Could not open %s twice: %s"), device,
			   strerror(errno));
		return false;
	}

	if(ioctl(if_fd, I_PUSH, "ip") < 0) {
		logger(LOG_ERR, _("Can't push IP module: %s"), strerror(errno));
		return false;
	}

	/* Assign ppa according to the unit number returned by tun device */
	if(ioctl(if_fd, IF_UNITSEL, (char *) &ppa) < 0) {
		logger(LOG_ERR, _("Can't set PPA %d: %s"), ppa, strerror(errno));
		return false;
	}

	if(ioctl(ip_fd, I_LINK, if_fd) < 0) {
		logger(LOG_ERR, _("Can't link TUN device to IP: %s"), strerror(errno));
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		asprintf(&iface, "tun%d", ppa);

	device_info = _("Solaris tun device");

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

	if((lenin = read(device_fd, packet->data + 14, MTU - 14)) <= 0) {
		logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			   device, strerror(errno));
		return false;
	}

	switch(packet->data[14] >> 4) {
		case 4:
			packet->data[12] = 0x08;
			packet->data[13] = 0x00;
			break;
		case 6:
			packet->data[12] = 0x86;
			packet->data[13] = 0xDD;
			break;
		default:
			ifdebug(TRAFFIC) logger(LOG_ERR,
					   _ ("Unknown IP version %d while reading packet from %s %s"),
					   packet->data[14] >> 4, device_info, device);
			return false;
	}

	packet->len = lenin + 14;

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

	if(write(device_fd, packet->data + 14, packet->len - 14) < 0) {
		logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info,
			   device, strerror(errno));
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
