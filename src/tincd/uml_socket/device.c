/*
    device.c -- UML network socket
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

    $Id: device.c,v 1.1 2005-03-17 23:59:38 pcg Exp $
*/

#include <time.h>
#include <sys/time.h>
#include <sys/un.h>

int device_fd = -1;
static int listen_fd = -1;
static int request_fd = -1;
static int data_fd = -1;
static int write_fd = -1;
static int state = 0;
char *device;
char *iface = NULL;
char *device_info;

bool running;

static int device_total_in = 0;
static int device_total_out = 0;

enum request_type { REQ_NEW_CONTROL };

static struct request {
  uint32_t magic;
  uint32_t version;
  enum request_type type;
  struct sockaddr_un sock;
} request;

static struct sockaddr_un data_sun;

bool setup_device(void)
{
	struct sockaddr_un listen_sun;
	static const int one = 1;
	struct {
		char zero;
		int pid;
		int usecs;
	} name;
	struct timeval tv;

	cp();

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
                return false;

	get_config_string(lookup_config(config_tree, "Interface"), &iface);

	device_info = _("UML network socket");

	if((write_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		logger(LOG_ERR, _("Could not open write %s: %s"), device_info, strerror(errno));
		running = false;
		return false;
	}

	setsockopt(write_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

	if(fcntl(write_fd, F_SETFL, O_NONBLOCK) < 0) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
		running = false;
		return false;
	}

	if((data_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		logger(LOG_ERR, _("Could not open data %s: %s"), device_info, strerror(errno));
		running = false;
		return false;
	}

	setsockopt(data_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

	if(fcntl(data_fd, F_SETFL, O_NONBLOCK) < 0) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
		running = false;
		return false;
	}

	name.zero = 0;
	name.pid = getpid();
	gettimeofday(&tv, NULL);
	name.usecs = tv.tv_usec;
	data_sun.sun_family = AF_UNIX;
	memcpy(&data_sun.sun_path, &name, sizeof name);
	
	if(bind(data_fd, (struct sockaddr *)&data_sun, sizeof data_sun) < 0) {
		logger(LOG_ERR, _("Could not bind data %s: %s"), device_info, strerror(errno));
		running = false;
		return false;
	}

	if((listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		logger(LOG_ERR, _("Could not open %s: %s"), device_info,
			   strerror(errno));
		return false;
	}

	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

	if(fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
		return false;
	}

	listen_sun.sun_family = AF_UNIX;
	strncpy(listen_sun.sun_path, device, sizeof listen_sun.sun_path);
	if(bind(listen_fd, (struct sockaddr *)&listen_sun, sizeof listen_sun) < 0) {
		logger(LOG_ERR, _("Could not bind %s to %s: %s"), device_info, device, strerror(errno));
		return false;
	}

	if(listen(listen_fd, 1) < 0) {
		logger(LOG_ERR, _("Could not listen on %s %s: %s"), device_info, device, strerror(errno));
		return false;
	}

	device_fd = listen_fd;
	state = 0;

	logger(LOG_INFO, _("%s is a %s"), device, device_info);

	if(routing_mode == RMODE_ROUTER)
		overwrite_mac = true;

	return true;
}

void close_device(void)
{
	cp();

	if(listen_fd >= 0)
		close(listen_fd);

	if(request_fd >= 0)
		close(request_fd);

	if(data_fd >= 0)
		close(data_fd);

	if(write_fd >= 0)
		close(write_fd);

	unlink(device);
}

bool read_packet(vpn_packet_t *packet)
{
	int lenin;

	cp();

	switch(state) {
		case 0: {
			struct sockaddr sa;
			socklen_t salen = sizeof sa;

			request_fd = accept(listen_fd, &sa, &salen);
			if(request_fd < 0) {
				logger(LOG_ERR, _("Could not accept connection to %s %s: %s"), device_info, device, strerror(errno));
				return false;
			}

			if(fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
				logger(LOG_ERR, _("System call `%s' failed: %s"), "fcntl", strerror(errno));
				running = false;
				return false;
			}

			close(listen_fd);
			listen_fd = -1;
			device_fd = request_fd;
			state = 1;

			return false;
		}

		case 1: {
			if((lenin = read(request_fd, &request, sizeof request)) != sizeof request) {
				logger(LOG_ERR, _("Error while reading request from %s %s: %s"), device_info,
					   device, strerror(errno));
				running = false;
				return false;
			}

			if(request.magic != 0xfeedface || request.version != 3 || request.type != REQ_NEW_CONTROL) {
				logger(LOG_ERR, _("Unknown magic %x, version %d, request type %d from %s %s"),
						request.magic, request.version, request.type, device_info, device);
				running = false;
				return false;
			}

			if(connect(write_fd, (sockaddr *)&request.sock, sizeof request.sock) < 0) {
				logger(LOG_ERR, _("Could not bind write %s: %s"), device_info, strerror(errno));
				running = false;
				return false;
			}

			write(request_fd, &data_sun, sizeof data_sun);
			device_fd = data_fd;

			logger(LOG_INFO, _("Connection with UML established"));

			state = 2;
			return false;
		}

		case 2: {
			if((lenin = read(data_fd, packet->data, MTU)) <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
					   device, strerror(errno));
				running = false;
				return false;
			}

			packet->len = lenin;

			device_total_in += packet->len;

			ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
					   device_info);

			return true;
		}
	}
}

bool write_packet(vpn_packet_t *packet)
{
	cp();

	if(state != 2) {
		ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Dropping packet of %d bytes to %s: not connected to UML yet"),
				packet->len, device_info);
		return false;
	}

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(write(write_fd, packet->data, packet->len) < 0) {
		if(errno != EINTR && errno != EAGAIN) {
			logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device, strerror(errno));
			running = false;
		}

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
