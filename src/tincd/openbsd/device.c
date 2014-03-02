/*
    device.c -- Interaction with OpenBSD tun device
    Copyright (C) 2001-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2001-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: device.c,v 1.1 2003-10-14 03:22:09 pcg Exp $
*/

#include <sys/uio.h>


#define DEFAULT_DEVICE "/dev/tun0"

#define DEVICE_TYPE_ETHERTAP 0
#define DEVICE_TYPE_TUNTAP 1

int device_fd = -1;
char *device;
char *iface;
char *device_info;

int device_total_in = 0;
int device_total_out = 0;

bool setup_device(void)
{
	cp();

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = DEFAULT_DEVICE;

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = rindex(device, '/') ? rindex(device, '/') + 1 : device;
	if((device_fd = open(device, O_RDWR | O_NONBLOCK)) < 0) {
		logger(LOG_ERR, _("Could not open %s: %s"), device, strerror(errno));
		return false;
	}

	device_info = _("OpenBSD tun device");

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
	u_int32_t type;
	struct iovec vector[2] = {{&type, sizeof(type)}, {packet->data + 14, MTU - 14}};

	cp();

	if((lenin = readv(device_fd, vector, 2)) <= 0) {
		logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			   device, strerror(errno));
		return false;
	}

	switch (ntohl(type)) {
	        case AF_INET:
		        packet->data[12] = 0x8;
		        packet->data[13] = 0x0;
		        break;

	        case AF_INET6:
		        packet->data[12] = 0x86;
		        packet->data[13] = 0xDD;
		        break;

	        default:
			ifdebug(TRAFFIC) logger(LOG_ERR,
				           _ ("Unknown address family %d while reading packet from %s %s"),
				           ntohl(type), device_info, device);
		        return false;
	}

	packet->len = lenin + 10;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
			   device_info);

	return true;
}

bool write_packet(vpn_packet_t *packet)
{
	u_int32_t type;
	struct iovec vector[2];
	int af;

	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	af = (packet->data[12] << 8) + packet->data[13];

	switch (af) {
	case 0x800:
		type = htonl(AF_INET);
		break;
	case 0x86DD:
		type = htonl(AF_INET6);
		break;
	default:
		ifdebug(TRAFFIC) logger(LOG_ERR,
				   _("Unknown address family %d while writing packet to %s %s"),
				   af, device_info, device);
		return false;
	}

	vector[0].iov_base = &type;
	vector[0].iov_len = sizeof(type);
	vector[1].iov_base = packet->data + 14;
	vector[1].iov_len = packet->len - 14;

	if(writev(device_fd, vector, 2) < 0) {
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
