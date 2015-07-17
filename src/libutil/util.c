/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "config.h"
#include "util.h"
#include "cfg_file.h"
#include "main.h"
#include "filter.h"
#include "message.h"

#include "xxhash.h"
#include "ottery.h"
#include "cryptobox.h"

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_READPASSPHRASE_H
#include <readpassphrase.h>
#endif

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

/* Check log messages intensity once per minute */
#define CHECK_TIME 60
/* More than 2 log messages per second */
#define BUF_INTENSITY 2
/* Default connect timeout for sync sockets */
#define CONNECT_TIMEOUT 3

gint
rspamd_socket_nonblocking (gint fd)
{
	gint ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

gint
rspamd_socket_blocking (gint fd)
{
	gint ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl & (~O_NONBLOCK)) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}
	return 0;
}

gint
rspamd_socket_poll (gint fd, gint timeout, short events)
{
	gint r;
	struct pollfd fds[1];

	fds->fd = fd;
	fds->events = events;
	fds->revents = 0;
	while ((r = poll (fds, 1, timeout)) < 0) {
		if (errno != EINTR) {
			break;
		}
	}

	return r;
}

gint
rspamd_socket_create (gint af, gint type, gint protocol, gboolean async)
{
	gint fd;

	fd = socket (af, type, protocol);
	if (fd == -1) {
		msg_warn ("socket failed: %d, '%s'", errno, strerror (errno));
		return -1;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		close (fd);
		return -1;
	}
	if (async) {
		if (rspamd_socket_nonblocking (fd) == -1) {
			close (fd);
			return -1;
		}
	}

	return fd;
}

static gint
rspamd_inet_socket_create (gint type, struct addrinfo *addr, gboolean is_server,
	gboolean async, GList **list)
{
	gint fd = -1, r, optlen, on = 1, s_error;
	struct addrinfo *cur;

	cur = addr;
	while (cur) {
		/* Create socket */
		fd = rspamd_socket_create (cur->ai_family, type, cur->ai_protocol, TRUE);
		if (fd == -1) {
			goto out;
		}

		if (is_server) {
			setsockopt (fd,
				SOL_SOCKET,
				SO_REUSEADDR,
				(const void *)&on,
				sizeof (gint));
#ifdef HAVE_IPV6_V6ONLY
			if (cur->ai_family == AF_INET6) {
				setsockopt (fd,
					IPPROTO_IPV6,
					IPV6_V6ONLY,
					(const void *)&on,
					sizeof (gint));
			}
#endif
			r = bind (fd, cur->ai_addr, cur->ai_addrlen);
		}
		else {
			r = connect (fd, cur->ai_addr, cur->ai_addrlen);
		}

		if (r == -1) {
			if (errno != EINPROGRESS) {
				msg_warn ("bind/connect failed: %d, '%s'", errno,
					strerror (errno));
				goto out;
			}
			if (!async) {
				/* Try to poll */
				if (rspamd_socket_poll (fd, CONNECT_TIMEOUT * 1000,
					POLLOUT) <= 0) {
					errno = ETIMEDOUT;
					msg_warn ("bind/connect failed: timeout");
					goto out;
				}
				else {
					/* Make synced again */
					if (rspamd_socket_blocking (fd) < 0) {
						goto out;
					}
				}
			}
		}
		else {
			/* Still need to check SO_ERROR on socket */
			optlen = sizeof (s_error);
			getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
			if (s_error) {
				errno = s_error;
				goto out;
			}
		}
		if (list == NULL) {
			/* Go out immediately */
			break;
		}
		else if (fd != -1) {
			*list = g_list_prepend (*list, GINT_TO_POINTER (fd));
			cur = cur->ai_next;
			continue;
		}
out:
		if (fd != -1) {
			close (fd);
		}
		fd = -1;
		cur = cur->ai_next;
	}
	return (fd);
}

gint
rspamd_socket_tcp (struct addrinfo *addr, gboolean is_server, gboolean async)
{
	return rspamd_inet_socket_create (SOCK_STREAM, addr, is_server, async, NULL);
}

gint
rspamd_socket_udp (struct addrinfo *addr, gboolean is_server, gboolean async)
{
	return rspamd_inet_socket_create (SOCK_DGRAM, addr, is_server, async, NULL);
}

gint
rspamd_socket_unix (const gchar *path,
	struct sockaddr_un *addr,
	gint type,
	gboolean is_server,
	gboolean async)
{
	gint fd = -1, s_error, r, optlen, serrno, on = 1;
	struct stat st;

	if (path == NULL)
		return -1;

	addr->sun_family = AF_UNIX;

	rspamd_strlcpy (addr->sun_path, path, sizeof (addr->sun_path));
#ifdef FREEBSD
	addr->sun_len = SUN_LEN (addr);
#endif

	if (is_server) {
		/* Unlink socket if it exists already */
		if (lstat (addr->sun_path, &st) != -1) {
			if (S_ISSOCK (st.st_mode)) {
				if (unlink (addr->sun_path) == -1) {
					msg_warn ("unlink %s failed: %d, '%s'",
						addr->sun_path,
						errno,
						strerror (errno));
					goto out;
				}
			}
			else {
				msg_warn ("%s is not a socket", addr->sun_path);
				goto out;
			}
		}
	}
	fd = socket (PF_LOCAL, type, 0);

	if (fd == -1) {
		msg_warn ("socket failed %s: %d, '%s'",
			addr->sun_path,
			errno,
			strerror (errno));
		return -1;
	}

	if (rspamd_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed %s: %d, '%s'", addr->sun_path, errno,
			strerror (errno));
		goto out;
	}
	if (is_server) {
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on,
			sizeof (gint));
		r = bind (fd, (struct sockaddr *)addr, SUN_LEN (addr));
	}
	else {
		r = connect (fd, (struct sockaddr *)addr, SUN_LEN (addr));
	}

	if (r == -1) {
		if (errno != EINPROGRESS) {
			msg_warn ("bind/connect failed %s: %d, '%s'",
				addr->sun_path,
				errno,
				strerror (errno));
			goto out;
		}
		if (!async) {
			/* Try to poll */
			if (rspamd_socket_poll (fd, CONNECT_TIMEOUT * 1000, POLLOUT) <= 0) {
				errno = ETIMEDOUT;
				msg_warn ("bind/connect failed %s: timeout", addr->sun_path);
				goto out;
			}
			else {
				/* Make synced again */
				if (rspamd_socket_blocking (fd) < 0) {
					goto out;
				}
			}
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof (s_error);
		getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
		if (s_error) {
			errno = s_error;
			goto out;
		}
	}


	return (fd);

out:
	serrno = errno;
	if (fd != -1) {
		close (fd);
	}
	errno = serrno;
	return (-1);
}

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
gint
rspamd_socket (const gchar *credits, guint16 port,
	gint type, gboolean async, gboolean is_server, gboolean try_resolve)
{
	struct sockaddr_un un;
	struct stat st;
	struct addrinfo hints, *res;
	gint r;
	gchar portbuf[8];

	if (*credits == '/') {
		if (is_server) {
			return rspamd_socket_unix (credits, &un, type, is_server, async);
		}
		else {
			r = stat (credits, &st);
			if (r == -1) {
				/* Unix socket doesn't exists it must be created first */
				errno = ENOENT;
				return -1;
			}
			else {
				if ((st.st_mode & S_IFSOCK) == 0) {
					/* Path is not valid socket */
					errno = EINVAL;
					return -1;
				}
				else {
					return rspamd_socket_unix (credits,
							   &un,
							   type,
							   is_server,
							   async);
				}
			}
		}
	}
	else {
		/* TCP related part */
		memset (&hints, 0, sizeof (hints));
		hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
		hints.ai_socktype = type; /* Type of the socket */
		hints.ai_flags = is_server ? AI_PASSIVE : 0;
		hints.ai_protocol = 0;           /* Any protocol */
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		if (!try_resolve) {
			hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
		}

		rspamd_snprintf (portbuf, sizeof (portbuf), "%d", (int)port);
		if ((r = getaddrinfo (credits, portbuf, &hints, &res)) == 0) {
			r = rspamd_inet_socket_create (type, res, is_server, async, NULL);
			freeaddrinfo (res);
			return r;
		}
		else {
			msg_err ("address resolution for %s failed: %s",
				credits,
				gai_strerror (r));
			return FALSE;
		}
	}
}

/**
 * Make universal stream socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
GList *
rspamd_sockets_list (const gchar *credits, guint16 port,
	gint type, gboolean async, gboolean is_server, gboolean try_resolve)
{
	struct sockaddr_un un;
	struct stat st;
	struct addrinfo hints, *res;
	gint r, fd = -1, serrno;
	gchar portbuf[8], **strv, **cur;
	GList *result = NULL, *rcur;

	strv = g_strsplit_set (credits, ",", -1);
	if (strv == NULL) {
		msg_err ("invalid sockets credentials: %s", credits);
		return NULL;
	}
	cur = strv;
	while (*cur != NULL) {
		if (*credits == '/') {
			if (is_server) {
				fd = rspamd_socket_unix (credits, &un, type, is_server, async);
			}
			else {
				r = stat (credits, &st);
				if (r == -1) {
					/* Unix socket doesn't exists it must be created first */
					errno = ENOENT;
					goto err;
				}
				else {
					if ((st.st_mode & S_IFSOCK) == 0) {
						/* Path is not valid socket */
						errno = EINVAL;
						goto err;
					}
					else {
						fd = rspamd_socket_unix (credits,
								&un,
								type,
								is_server,
								async);
					}
				}
			}
			if (fd != -1) {
				result = g_list_prepend (result, GINT_TO_POINTER (fd));
			}
			else {
				goto err;
			}
		}
		else {
			/* TCP related part */
			memset (&hints, 0, sizeof (hints));
			hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
			hints.ai_socktype = type; /* Type of the socket */
			hints.ai_flags = is_server ? AI_PASSIVE : 0;
			hints.ai_protocol = 0;           /* Any protocol */
			hints.ai_canonname = NULL;
			hints.ai_addr = NULL;
			hints.ai_next = NULL;

			if (!try_resolve) {
				hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
			}

			rspamd_snprintf (portbuf, sizeof (portbuf), "%d", (int)port);
			if ((r = getaddrinfo (credits, portbuf, &hints, &res)) == 0) {
				fd = rspamd_inet_socket_create (type, res, is_server, async, &result);
				freeaddrinfo (res);

				if (result == NULL) {
					if (fd != -1) {
						close (fd);
					}

					goto err;
				}
			}
			else {
				msg_err ("address resolution for %s failed: %s",
					credits,
					gai_strerror (r));
				goto err;
			}
		}

		cur++;
	}

	g_strfreev (strv);
	return result;

err:
	g_strfreev (strv);
	serrno = errno;
	rcur = result;
	while (rcur != NULL) {
		fd = GPOINTER_TO_INT (rcur->data);
		if (fd != -1) {
			close (fd);
		}
		rcur = g_list_next (rcur);
	}
	if (result != NULL) {
		g_list_free (result);
	}

	errno = serrno;
	return NULL;
}

gint
rspamd_socketpair (gint pair[2])
{
	gint r;

	r = socketpair (AF_LOCAL, SOCK_STREAM, 0, pair);

	if (r == -1) {
		msg_warn ("socketpair failed: %d, '%s'", errno, strerror (
				errno), pair[0], pair[1]);
		return -1;
	}
	/* Set close on exec */
	if (fcntl (pair[0], F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}
	if (fcntl (pair[1], F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
		goto out;
	}

	return 0;

out:
	close (pair[0]);
	close (pair[1]);
	return (-1);
}

gint
rspamd_write_pid (struct rspamd_main *main)
{
	pid_t pid;

	if (main->cfg->pid_file == NULL) {
		return -1;
	}
	main->pfh = rspamd_pidfile_open (main->cfg->pid_file, 0644, &pid);

	if (main->pfh == NULL) {
		return -1;
	}

	if (main->is_privilleged) {
		/* Force root user as owner of pid file */
#ifdef HAVE_PIDFILE_FILENO
		if (fchown (pidfile_fileno (main->pfh), 0, 0) == -1) {
#else
		if (fchown (main->pfh->pf_fd, 0, 0) == -1) {
#endif
			msg_err ("cannot chown of pidfile %s to 0:0 user",
				main->cfg->pid_file);
		}
	}

	rspamd_pidfile_write (main->pfh);

	return 0;
}

#ifdef HAVE_SA_SIGINFO
void
rspamd_signals_init (struct sigaction *signals, void (*sig_handler)(gint,
	siginfo_t *,
	void *))
#else
void
rspamd_signals_init (struct sigaction *signals, void (*sig_handler)(gint))
#endif
{
	struct sigaction sigpipe_act;
	/* Setting up signal handlers */
	/* SIGUSR1 - reopen config file */
	/* SIGUSR2 - worker is ready for accept */
	sigemptyset (&signals->sa_mask);
	sigaddset (&signals->sa_mask, SIGTERM);
	sigaddset (&signals->sa_mask, SIGINT);
	sigaddset (&signals->sa_mask, SIGHUP);
	sigaddset (&signals->sa_mask, SIGCHLD);
	sigaddset (&signals->sa_mask, SIGUSR1);
	sigaddset (&signals->sa_mask, SIGUSR2);
	sigaddset (&signals->sa_mask, SIGALRM);


#ifdef HAVE_SA_SIGINFO
	signals->sa_flags = SA_SIGINFO;
	signals->sa_handler = NULL;
	signals->sa_sigaction = sig_handler;
#else
	signals->sa_handler = sig_handler;
	signals->sa_flags = 0;
#endif
	sigaction (SIGTERM, signals, NULL);
	sigaction (SIGINT,	signals, NULL);
	sigaction (SIGHUP,	signals, NULL);
	sigaction (SIGCHLD, signals, NULL);
	sigaction (SIGUSR1, signals, NULL);
	sigaction (SIGUSR2, signals, NULL);
	sigaction (SIGALRM, signals, NULL);

	/* Ignore SIGPIPE as we handle write errors manually */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);
}

static void
pass_signal_cb (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_worker *cur = value;
	gint signo = GPOINTER_TO_INT (ud);

	kill (cur->pid, signo);
}

void
rspamd_pass_signal (GHashTable * workers, gint signo)
{
	g_hash_table_foreach (workers, pass_signal_cb, GINT_TO_POINTER (signo));
}

static const guchar lc_map[256] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
		0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

void
rspamd_str_lc (gchar *str, guint size)
{
	guint leftover = size % 4;
	guint fp, i;
	const uint8_t* s = (const uint8_t*) str;
	gchar *dest = str;
	guchar c1, c2, c3, c4;

	fp = size - leftover;

	for (i = 0; i != fp; i += 4) {
		c1 = s[i], c2 = s[i + 1], c3 = s[i + 2], c4 = s[i + 3];
		dest[0] = lc_map[c1];
		dest[1] = lc_map[c2];
		dest[2] = lc_map[c3];
		dest[3] = lc_map[c4];
		dest += 4;
	}

	switch (leftover) {
	case 3:
		*dest++ = lc_map[(guchar)str[i++]];
	case 2:
		*dest++ = lc_map[(guchar)str[i++]];
	case 1:
		*dest++ = lc_map[(guchar)str[i]];
	}

}

/*
 * The purpose of this function is fast and in place conversion of a unicode
 * string to lower case, so some locale peculiarities are simply ignored
 * If the target string is longer than initial one, then we just trim it
 */
void
rspamd_str_lc_utf8 (gchar *str, guint size)
{
	const gchar *s = str, *p;
	gchar *d = str, tst[6];
	gint remain = size;
	gint r;
	gunichar uc;

	while (remain > 0) {
		uc = g_utf8_get_char (s);
		uc = g_unichar_tolower (uc);
		p = g_utf8_next_char (s);

		if (p - s > remain) {
			break;
		}

		if (remain >= 6) {
			r = g_unichar_to_utf8 (uc, d);
		}
		else {
			/* We must be cautious here to avoid broken unicode being append */
			r = g_unichar_to_utf8 (uc, tst);
			if (r > remain) {
				break;
			}
			else {
				memcpy (d, tst, r);
			}
		}
		remain -= r;
		s = p;
		d += r;
	}
}

#ifndef HAVE_SETPROCTITLE

static gchar *title_buffer = 0;
static size_t title_buffer_size = 0;
static gchar *title_progname, *title_progname_full;

gint
setproctitle (const gchar *fmt, ...)
{
	if (!title_buffer || !title_buffer_size) {
		errno = ENOMEM;
		return -1;
	}

	memset (title_buffer, '\0', title_buffer_size);

	ssize_t written;

	if (fmt) {
		ssize_t written2;
		va_list ap;

		written = snprintf (title_buffer,
				title_buffer_size,
				"%s: ",
				title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;

		va_start (ap, fmt);
		written2 = vsnprintf (title_buffer + written,
				title_buffer_size - written,
				fmt,
				ap);
		va_end (ap);
		if (written2 < 0 || (size_t) written2 >= title_buffer_size - written)
			return -1;
	}
	else {
		written = snprintf (title_buffer,
				title_buffer_size,
				"%s",
				title_progname);
		if (written < 0 || (size_t) written >= title_buffer_size)
			return -1;
	}

	written = strlen (title_buffer);
	memset (title_buffer + written, '\0', title_buffer_size - written);

	return 0;
}

/*
   It has to be _init function, because __attribute__((constructor))
   functions gets called without arguments.
 */

gint
init_title (gint argc, gchar *argv[], gchar *envp[])
{
#if defined(DARWIN) || defined(SOLARIS)
	/* XXX: try to handle these OSes too */
	return 0;
#else
	gchar *begin_of_buffer = 0, *end_of_buffer = 0;
	gint i;

	for (i = 0; i < argc; ++i) {
		if (!begin_of_buffer)
			begin_of_buffer = argv[i];
		if (!end_of_buffer || end_of_buffer + 1 == argv[i])
			end_of_buffer = argv[i] + strlen (argv[i]);
	}

	for (i = 0; envp[i]; ++i) {
		if (!begin_of_buffer)
			begin_of_buffer = envp[i];
		if (!end_of_buffer || end_of_buffer + 1 == envp[i])
			end_of_buffer = envp[i] + strlen (envp[i]);
	}

	if (!end_of_buffer)
		return 0;

	gchar **new_environ = g_malloc ((i + 1) * sizeof (envp[0]));

	if (!new_environ)
		return 0;

	for (i = 0; envp[i]; ++i) {
		if (!(new_environ[i] = g_strdup (envp[i])))
			goto cleanup_enomem;
	}
	new_environ[i] = 0;

	if (program_invocation_name) {
		title_progname_full = g_strdup (program_invocation_name);

		if (!title_progname_full)
			goto cleanup_enomem;

		gchar *p = strrchr (title_progname_full, '/');

		if (p)
			title_progname = p + 1;
		else
			title_progname = title_progname_full;

		program_invocation_name = title_progname_full;
		program_invocation_short_name = title_progname;
	}

	environ = new_environ;
	title_buffer = begin_of_buffer;
	title_buffer_size = end_of_buffer - begin_of_buffer;

	return 0;

cleanup_enomem:
	for (--i; i >= 0; --i) {
		g_free (new_environ[i]);
	}
	g_free (new_environ);
	return 0;
#endif
}
#endif

#ifndef HAVE_PIDFILE
extern gchar *__progname;
static gint _rspamd_pidfile_remove (rspamd_pidfh_t *pfh, gint freeit);

static gint
rspamd_pidfile_verify (rspamd_pidfh_t *pfh)
{
	struct stat sb;

	if (pfh == NULL || pfh->pf_fd == -1)
		return (-1);
	/*
	 * Check remembered descriptor.
	 */
	if (fstat (pfh->pf_fd, &sb) == -1)
		return (errno);
	if (sb.st_dev != pfh->pf_dev || sb.st_ino != pfh->pf_ino)
		return -1;
	return 0;
}

static gint
rspamd_pidfile_read (const gchar *path, pid_t * pidptr)
{
	gchar buf[16], *endptr;
	gint error, fd, i;

	fd = open (path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read (fd, buf, sizeof (buf) - 1);
	error = errno;              /* Remember errno in case close() wants to change it. */
	close (fd);
	if (i == -1)
		return error;
	else if (i == 0)
		return EAGAIN;
	buf[i] = '\0';

	*pidptr = strtol (buf, &endptr, 10);
	if (endptr != &buf[i])
		return EINVAL;

	return 0;
}

rspamd_pidfh_t *
rspamd_pidfile_open (const gchar *path, mode_t mode, pid_t * pidptr)
{
	rspamd_pidfh_t *pfh;
	struct stat sb;
	gint error, fd, len, count;
	struct timespec rqtp;

	pfh = g_malloc (sizeof (*pfh));
	if (pfh == NULL)
		return NULL;

	if (path == NULL)
		len = snprintf (pfh->pf_path,
				sizeof (pfh->pf_path),
				"/var/run/%s.pid",
				g_get_prgname ());
	else
		len = snprintf (pfh->pf_path, sizeof (pfh->pf_path), "%s", path);
	if (len >= (gint)sizeof (pfh->pf_path)) {
		g_free (pfh);
		errno = ENAMETOOLONG;
		return NULL;
	}

	/*
	 * Open the PID file and obtain exclusive lock.
	 * We truncate PID file here only to remove old PID immediatelly,
	 * PID file will be truncated again in pidfile_write(), so
	 * pidfile_write() can be called multiple times.
	 */
	fd = open (pfh->pf_path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, mode);
	rspamd_file_lock (fd, TRUE);
	if (fd == -1) {
		count = 0;
		rqtp.tv_sec = 0;
		rqtp.tv_nsec = 5000000;
		if (errno == EWOULDBLOCK && pidptr != NULL) {
again:
			errno = rspamd_pidfile_read (pfh->pf_path, pidptr);
			if (errno == 0)
				errno = EEXIST;
			else if (errno == EAGAIN) {
				if (++count <= 3) {
					nanosleep (&rqtp, 0);
					goto again;
				}
			}
		}
		g_free (pfh);
		return NULL;
	}
	/*
	 * Remember file information, so in pidfile_write() we are sure we write
	 * to the proper descriptor.
	 */
	if (fstat (fd, &sb) == -1) {
		error = errno;
		unlink (pfh->pf_path);
		close (fd);
		g_free (pfh);
		errno = error;
		return NULL;
	}

	pfh->pf_fd = fd;
	pfh->pf_dev = sb.st_dev;
	pfh->pf_ino = sb.st_ino;

	return pfh;
}

gint
rspamd_pidfile_write (rspamd_pidfh_t *pfh)
{
	gchar pidstr[16];
	gint error, fd;

	/*
	 * Check remembered descriptor, so we don't overwrite some other
	 * file if pidfile was closed and descriptor reused.
	 */
	errno = rspamd_pidfile_verify (pfh);
	if (errno != 0) {
		/*
		 * Don't close descriptor, because we are not sure if it's ours.
		 */
		return -1;
	}
	fd = pfh->pf_fd;

	/*
	 * Truncate PID file, so multiple calls of pidfile_write() are allowed.
	 */
	if (ftruncate (fd, 0) == -1) {
		error = errno;
		_rspamd_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	rspamd_snprintf (pidstr, sizeof (pidstr), "%P", getpid ());
	if (pwrite (fd, pidstr, strlen (pidstr), 0) != (ssize_t) strlen (pidstr)) {
		error = errno;
		_rspamd_pidfile_remove (pfh, 0);
		errno = error;
		return -1;
	}

	return 0;
}

gint
rspamd_pidfile_close (rspamd_pidfh_t *pfh)
{
	gint error;

	error = rspamd_pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (close (pfh->pf_fd) == -1)
		error = errno;
	g_free (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

static gint
_rspamd_pidfile_remove (rspamd_pidfh_t *pfh, gint freeit)
{
	gint error;

	error = rspamd_pidfile_verify (pfh);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (unlink (pfh->pf_path) == -1)
		error = errno;
	if (!rspamd_file_unlock (pfh->pf_fd, FALSE)) {
		if (error == 0)
			error = errno;
	}
	if (close (pfh->pf_fd) == -1) {
		if (error == 0)
			error = errno;
	}
	if (freeit)
		g_free (pfh);
	else
		pfh->pf_fd = -1;
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

gint
rspamd_pidfile_remove (rspamd_pidfh_t *pfh)
{

	return (_rspamd_pidfile_remove (pfh, 1));
}
#endif

/* Replace %r with rcpt value and %f with from value, new string is allocated in pool */
gchar *
resolve_stat_filename (rspamd_mempool_t * pool,
	gchar *pattern,
	gchar *rcpt,
	gchar *from)
{
	gint need_to_format = 0, len = 0;
	gint rcptlen, fromlen;
	gchar *c = pattern, *new, *s;

	if (rcpt) {
		rcptlen = strlen (rcpt);
	}
	else {
		rcptlen = 0;
	}

	if (from) {
		fromlen = strlen (from);
	}
	else {
		fromlen = 0;
	}

	/* Calculate length */
	while (*c++) {
		if (*c == '%' && *(c + 1) == 'r') {
			len += rcptlen;
			c += 2;
			need_to_format = 1;
			continue;
		}
		else if (*c == '%' && *(c + 1) == 'f') {
			len += fromlen;
			c += 2;
			need_to_format = 1;
			continue;
		}
		len++;
	}

	/* Do not allocate extra memory if we do not need to format string */
	if (!need_to_format) {
		return pattern;
	}

	/* Allocate new string */
	new = rspamd_mempool_alloc (pool, len);
	c = pattern;
	s = new;

	/* Format string */
	while (*c++) {
		if (*c == '%' && *(c + 1) == 'r') {
			c += 2;
			memcpy (s, rcpt, rcptlen);
			s += rcptlen;
			continue;
		}
		else if (*c == '%' && *(c + 1) == 'r') {
			c += 2;
			memcpy (s, from, fromlen);
			s += fromlen;
			continue;
		}
		*s++ = *c;
	}

	*s = '\0';

	return new;
}

const gchar *
calculate_check_time (gdouble start_real, gdouble start_virtual, gint resolution,
	guint32 *scan_time)
{
	double vdiff, diff, end_real, end_virtual;
	static gchar res[64];
	static gchar fmt[sizeof ("%.10f ms real, %.10f ms virtual")];

	end_real = rspamd_get_ticks ();
	end_virtual = rspamd_get_virtual_ticks ();
	vdiff = (end_virtual - start_virtual) * 1000;
	diff = (end_real - start_real) * 1000;

	*scan_time = diff;

	sprintf (fmt, "%%.%dfms real, %%.%dfms virtual", resolution, resolution);
	snprintf (res, sizeof (res), fmt, diff, vdiff);

	return (const gchar *)res;
}

#ifndef g_tolower
#   define g_tolower(x) (((x) >= 'A' && (x) <= 'Z') ? (x) - 'A' + 'a' : (x))
#endif


gboolean
rspamd_strcase_equal (gconstpointer v, gconstpointer v2)
{
	if (g_ascii_strcasecmp ((const gchar *)v, (const gchar *)v2) == 0) {
		return TRUE;
	}

	return FALSE;
}

static guint
rspamd_icase_hash (const gchar *in, gsize len)
{
	guint leftover = len % 4;
	guint fp, i;
	const uint8_t* s = (const uint8_t*) in;
	union {
		struct {
			guchar c1, c2, c3, c4;
		} c;
		guint32 pp;
	} u;
	XXH64_state_t st;

	fp = len - leftover;
	XXH64_reset (&st, rspamd_hash_seed ());

	for (i = 0; i != fp; i += 4) {
		u.c.c1 = s[i], u.c.c2 = s[i + 1], u.c.c3 = s[i + 2], u.c.c4 = s[i + 3];
		u.c.c1 = lc_map[u.c.c1];
		u.c.c2 = lc_map[u.c.c2];
		u.c.c3 = lc_map[u.c.c3];
		u.c.c4 = lc_map[u.c.c4];
		XXH64_update (&st, &u.pp, sizeof (u));
	}

	u.pp = 0;
	switch (leftover) {
	case 3:
		u.c.c3 = lc_map[(guchar)s[i++]];
	case 2:
		u.c.c2 = lc_map[(guchar)s[i++]];
	case 1:
		u.c.c1 = lc_map[(guchar)s[i]];
		XXH64_update (&st, &u.pp, leftover);
		break;
	}

	return XXH64_digest (&st);
}

guint
rspamd_strcase_hash (gconstpointer key)
{
	const gchar *p = key;
	gsize len;

	len = strlen (p);

	return rspamd_icase_hash (p, len);
}

guint
rspamd_str_hash (gconstpointer key)
{
	gsize len;

	len = strlen ((const gchar *)key);

	return XXH64 (key, len, rspamd_hash_seed ());
}

gboolean
rspamd_str_equal (gconstpointer v, gconstpointer v2)
{
	return strcmp ((const gchar *)v, (const gchar *)v2) == 0;
}

gboolean
rspamd_fstring_icase_equal (gconstpointer v, gconstpointer v2)
{
	const rspamd_fstring_t *f1 = v, *f2 = v2;
	if (f1->len == f2->len &&
		g_ascii_strncasecmp (f1->begin, f2->begin, f1->len) == 0) {
		return TRUE;
	}

	return FALSE;
}


guint
rspamd_fstring_icase_hash (gconstpointer key)
{
	const rspamd_fstring_t *f = key;

	return rspamd_icase_hash (f->begin, f->len);
}

gboolean
rspamd_gstring_icase_equal (gconstpointer v, gconstpointer v2)
{
	const GString *f1 = v, *f2 = v2;
	if (f1->len == f2->len &&
		g_ascii_strncasecmp (f1->str, f2->str, f1->len) == 0) {
		return TRUE;
	}

	return FALSE;
}


guint
rspamd_gstring_icase_hash (gconstpointer key)
{
	const GString *f = key;

	return rspamd_icase_hash (f->str, f->len);
}

void
gperf_profiler_init (struct rspamd_config *cfg, const gchar *descr)
{
#if defined(WITH_GPERF_TOOLS)
	gchar prof_path[PATH_MAX];

	if (getenv ("CPUPROFILE")) {

		/* disable inherited Profiler enabled in master process */
		ProfilerStop ();
	}
	/* Try to create temp directory for gmon.out and chdir to it */
	if (cfg->profile_path == NULL) {
		cfg->profile_path =
			g_strdup_printf ("%s/rspamd-profile", cfg->temp_dir);
	}

	snprintf (prof_path,
		sizeof (prof_path),
		"%s-%s.%d",
		cfg->profile_path,
		descr,
		(gint)getpid ());
	if (ProfilerStart (prof_path)) {
		/* start ITIMER_PROF timer */
		ProfilerRegisterThread ();
	}
	else {
		msg_warn ("cannot start google perftools profiler");
	}

#endif
}

#ifdef HAVE_FLOCK
/* Flock version */
gboolean
rspamd_file_lock (gint fd, gboolean async)
{
	gint flags;

	if (async) {
		flags = LOCK_EX | LOCK_NB;
	}
	else {
		flags = LOCK_EX;
	}

	if (flock (fd, flags) == -1) {
		if (async && errno == EAGAIN) {
			return FALSE;
		}
		msg_warn ("lock on file failed: %s", strerror (errno));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_file_unlock (gint fd, gboolean async)
{
	gint flags;

	if (async) {
		flags = LOCK_UN | LOCK_NB;
	}
	else {
		flags = LOCK_UN;
	}

	if (flock (fd, flags) == -1) {
		if (async && errno == EAGAIN) {
			return FALSE;
		}
		msg_warn ("lock on file failed: %s", strerror (errno));
		return FALSE;
	}

	return TRUE;

}
#else /* HAVE_FLOCK */
/* Fctnl version */
gboolean
rspamd_file_lock (gint fd, gboolean async)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	if (fcntl (fd, async ? F_SETLK : F_SETLKW, &fl) == -1) {
		if (async && (errno == EAGAIN || errno == EACCES)) {
			return FALSE;
		}
		msg_warn ("lock on file failed: %s", strerror (errno));
		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_file_unlock (gint fd, gboolean async)
{
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	if (fcntl (fd, async ? F_SETLK : F_SETLKW, &fl) == -1) {
		if (async && (errno == EAGAIN || errno == EACCES)) {
			return FALSE;
		}
		msg_warn ("lock on file failed: %s", strerror (errno));
		return FALSE;
	}

	return TRUE;

}
#endif /* HAVE_FLOCK */


#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void
g_ptr_array_unref (GPtrArray *array)
{
	g_ptr_array_free (array, TRUE);
}
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 14))
void
g_queue_clear (GQueue *queue)
{
	g_return_if_fail (queue != NULL);

	g_list_free (queue->head);
	queue->head = queue->tail = NULL;
	queue->length = 0;
}
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 30))
GPtrArray*
g_ptr_array_new_full (guint reserved_size,
		GDestroyNotify element_free_func)
{
	GPtrArray *array;

	array = g_ptr_array_sized_new (reserved_size);
	g_ptr_array_set_free_func (array, element_free_func);

	return array;
}
#endif


gsize
rspamd_strlcpy (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	const gchar *s = src;
	gsize n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0') {
				break;
			}
		}
	}

	if (n == 0 && siz != 0) {
		*d = '\0';
	}

	return (s - src - 1);    /* count does not include NUL */
}

gsize
rspamd_strlcpy_tolower (gchar *dst, const gchar *src, gsize siz)
{
	gchar *d = dst;
	const gchar *s = src;
	gsize n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = g_ascii_tolower (*s++)) == '\0') {
				break;
			}
		}
	}

	if (n == 0 && siz != 0) {
		*d = '\0';
	}

	return (s - src - 1);    /* count does not include NUL */
}

guint
rspamd_url_hash (gconstpointer u)
{
	const struct rspamd_url *url = u;
	XXH64_state_t st;

	XXH64_reset (&st, rspamd_hash_seed ());

	if (url->hostlen > 0) {
		XXH64_update (&st, url->host, url->hostlen);
	}
	if (url->userlen > 0) {
		XXH64_update (&st, url->user, url->userlen);
	}
	XXH64_update (&st, &url->is_phished, sizeof (url->is_phished));

	return XXH64_digest (&st);
}

/* Compare two emails for building emails tree */
gboolean
rspamd_emails_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_url *u1 = a, *u2 = b;
	gint r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return FALSE;
	}
	else {
		if ((r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen)) == 0) {
			if (u1->userlen != u2->userlen || u1->userlen == 0) {
				return FALSE;
			}
			else {
				return g_ascii_strncasecmp (u1->user, u2->user, u1->userlen) == 0;
			}
		}
		else {
			return r == 0;
		}
	}

	return FALSE;
}

gboolean
rspamd_urls_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_url *u1 = a, *u2 = b;
	int r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return FALSE;
	}
	else {
		r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen);
		if (r == 0 && u1->is_phished != u2->is_phished) {
			/* Always insert phished urls to the tree */
			return FALSE;
		}
	}

	return r == 0;
}

/*
 * Find the first occurrence of find in s, ignore case.
 */
gchar *
rspamd_strncasestr (const gchar *s, const gchar *find, gint len)
{
	gchar c, sc;
	gsize mlen;

	if ((c = *find++) != 0) {
		c = g_ascii_tolower (c);
		mlen = strlen (find);
		do {
			do {
				if ((sc = *s++) == 0 || len-- == 0)
					return (NULL);
			} while (g_ascii_tolower (sc) != c);
		} while (g_ascii_strncasecmp (s, find, mlen) != 0);
		s--;
	}
	return ((gchar *)s);
}

/*
 * Try to convert string of length to long
 */
gboolean
rspamd_strtol (const gchar *s, gsize len, glong *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	glong v = 0;
	const glong cutoff = G_MAXLONG / 10, cutlim = G_MAXLONG % 10;
	gboolean neg;

	/* Case negative values */
	if (*p == '-') {
		neg = TRUE;
		p++;
	}
	else {
		neg = FALSE;
	}
	/* Some preparations for range errors */

	while (p < end) {
		c = *p;
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && c > cutlim)) {
				/* Range error */
				*value = neg ? G_MINLONG : G_MAXLONG;
				return FALSE;
			}
			else {
				v *= 10;
				v += c;
			}
		}
		else {
			return FALSE;
		}
		p++;
	}

	*value = neg ? -(v) : v;
	return TRUE;
}

/*
 * Try to convert string of length to long
 */
gboolean
rspamd_strtoul (const gchar *s, gsize len, gulong *value)
{
	const gchar *p = s, *end = s + len;
	gchar c;
	gulong v = 0;
	const gulong cutoff = G_MAXULONG / 10, cutlim = G_MAXULONG % 10;

	/* Some preparations for range errors */
	while (p < end) {
		c = *p;
		if (c >= '0' && c <= '9') {
			c -= '0';
			if (v > cutoff || (v == cutoff && (guint8)c > cutlim)) {
				/* Range error */
				*value = G_MAXULONG;
				return FALSE;
			}
			else {
				v *= 10;
				v += c;
			}
		}
		else {
			return FALSE;
		}
		p++;
	}

	*value = v;
	return TRUE;
}

gint
rspamd_fallocate (gint fd, off_t offset, off_t len)
{
#if defined(HAVE_FALLOCATE)
	return fallocate (fd, 0, offset, len);
#elif defined(HAVE_POSIX_FALLOCATE)
	return posix_fallocate (fd, offset, len);
#else
	/* Return 0 as nothing can be done on this system */
	return 0;
#endif
}


/**
 * Create new mutex
 * @return mutex or NULL
 */
inline rspamd_mutex_t *
rspamd_mutex_new (void)
{
	rspamd_mutex_t *new;

	new = g_slice_alloc (sizeof (rspamd_mutex_t));
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_init (&new->mtx);
#else
	g_static_mutex_init (&new->mtx);
#endif

	return new;
}

/**
 * Lock mutex
 * @param mtx
 */
inline void
rspamd_mutex_lock (rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_lock (&mtx->mtx);
#else
	g_static_mutex_lock (&mtx->mtx);
#endif
}

/**
 * Unlock mutex
 * @param mtx
 */
inline void
rspamd_mutex_unlock (rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_unlock (&mtx->mtx);
#else
	g_static_mutex_unlock (&mtx->mtx);
#endif
}

void
rspamd_mutex_free (rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_mutex_clear (&mtx->mtx);
#endif
	g_slice_free1 (sizeof (rspamd_mutex_t), mtx);
}

/**
 * Create new rwlock
 * @return
 */
rspamd_rwlock_t *
rspamd_rwlock_new (void)
{
	rspamd_rwlock_t *new;

	new = g_malloc (sizeof (rspamd_rwlock_t));
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_init (&new->rwlock);
#else
	g_static_rw_lock_init (&new->rwlock);
#endif

	return new;
}

/**
 * Lock rwlock for writing
 * @param mtx
 */
inline void
rspamd_rwlock_writer_lock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_writer_lock (&mtx->rwlock);
#else
	g_static_rw_lock_writer_lock (&mtx->rwlock);
#endif
}

/**
 * Lock rwlock for reading
 * @param mtx
 */
inline void
rspamd_rwlock_reader_lock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_reader_lock (&mtx->rwlock);
#else
	g_static_rw_lock_reader_lock (&mtx->rwlock);
#endif
}

/**
 * Unlock rwlock from writing
 * @param mtx
 */
inline void
rspamd_rwlock_writer_unlock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_writer_unlock (&mtx->rwlock);
#else
	g_static_rw_lock_writer_unlock (&mtx->rwlock);
#endif
}

/**
 * Unlock rwlock from reading
 * @param mtx
 */
inline void
rspamd_rwlock_reader_unlock (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_reader_unlock (&mtx->rwlock);
#else
	g_static_rw_lock_reader_unlock (&mtx->rwlock);
#endif
}

void
rspamd_rwlock_free (rspamd_rwlock_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_rw_lock_clear (&mtx->rwlock);
#endif
	g_slice_free1 (sizeof (rspamd_rwlock_t), mtx);
}

struct rspamd_thread_data {
	gchar *name;
	gint id;
	GThreadFunc func;
	gpointer data;
};

static gpointer
rspamd_thread_func (gpointer ud)
{
	struct rspamd_thread_data *td = ud;
	sigset_t s_mask;

	/* Ignore signals in thread */
	sigemptyset (&s_mask);
	sigaddset (&s_mask, SIGTERM);
	sigaddset (&s_mask, SIGINT);
	sigaddset (&s_mask, SIGHUP);
	sigaddset (&s_mask, SIGCHLD);
	sigaddset (&s_mask, SIGUSR1);
	sigaddset (&s_mask, SIGUSR2);
	sigaddset (&s_mask, SIGALRM);
	sigaddset (&s_mask, SIGPIPE);

	sigprocmask (SIG_BLOCK, &s_mask, NULL);

	ud = td->func (td->data);
	g_free (td->name);
	g_free (td);

	return ud;
}

/**
 * Create new named thread
 * @param name name pattern
 * @param func function to start
 * @param data data to pass to function
 * @param err error pointer
 * @return new thread object that can be joined
 */
GThread *
rspamd_create_thread (const gchar *name,
	GThreadFunc func,
	gpointer data,
	GError **err)
{
	GThread *new;
	struct rspamd_thread_data *td;
	static gint32 id;
	guint r;

	r = strlen (name);
	td = g_malloc (sizeof (struct rspamd_thread_data));
	td->id = ++id;
	td->name = g_malloc (r + sizeof ("4294967296"));
	td->func = func;
	td->data = data;

	rspamd_snprintf (td->name, r + sizeof ("4294967296"), "%s-%d", name, id);
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	new = g_thread_try_new (td->name, rspamd_thread_func, td, err);
#else
	new = g_thread_create (rspamd_thread_func, td, TRUE, err);
#endif

	return new;
}

struct hash_copy_callback_data {
	gpointer (*key_copy_func)(gconstpointer data, gpointer ud);
	gpointer (*value_copy_func)(gconstpointer data, gpointer ud);
	gpointer ud;
	GHashTable *dst;
};

static void
copy_foreach_callback (gpointer key, gpointer value, gpointer ud)
{
	struct hash_copy_callback_data *cb = ud;
	gpointer nkey, nvalue;

	nkey = cb->key_copy_func ? cb->key_copy_func (key, cb->ud) : (gpointer)key;
	nvalue =
		cb->value_copy_func ? cb->value_copy_func (value,
			cb->ud) : (gpointer)value;
	g_hash_table_insert (cb->dst, nkey, nvalue);
}
/**
 * Deep copy of one hash table to another
 * @param src source hash
 * @param dst destination hash
 * @param key_copy_func function called to copy or modify keys (or NULL)
 * @param value_copy_func function called to copy or modify values (or NULL)
 * @param ud user data for copy functions
 */
void
rspamd_hash_table_copy (GHashTable *src, GHashTable *dst,
	gpointer (*key_copy_func)(gconstpointer data, gpointer ud),
	gpointer (*value_copy_func)(gconstpointer data, gpointer ud),
	gpointer ud)
{
	struct hash_copy_callback_data cb;
	if (src != NULL && dst != NULL) {
		cb.key_copy_func = key_copy_func;
		cb.value_copy_func = value_copy_func;
		cb.ud = ud;
		cb.dst = dst;
		g_hash_table_foreach (src, copy_foreach_callback, &cb);
	}
}

/**
 * Utility function to provide mem_pool copy for rspamd_hash_table_copy function
 * @param data string to copy
 * @param ud memory pool to use
 * @return
 */
gpointer
rspamd_str_pool_copy (gconstpointer data, gpointer ud)
{
	rspamd_mempool_t *pool = ud;

	return data ? rspamd_mempool_strdup (pool, data) : NULL;
}

static volatile sig_atomic_t saved_signo[NSIG];

static
void
read_pass_tmp_sig_handler (int s)
{

	saved_signo[s] = 1;
}

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

gint
rspamd_read_passphrase (gchar *buf, gint size, gint rwflag, gpointer key)
{
#ifdef HAVE_PASSPHRASE_H
	gint len = 0;
	gchar pass[BUFSIZ];

	if (readpassphrase ("Enter passphrase: ", buf, size, RPP_ECHO_OFF |
		RPP_REQUIRE_TTY) == NULL) {
		return 0;
	}

	return strlen (buf);
#else
	struct sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	struct sigaction savetstp, savettin, savettou, savepipe;
	struct termios term, oterm;
	gint input, output, i;
	gchar *end, *p, ch;

restart:
	if ((input = output = open (_PATH_TTY, O_RDWR)) == -1) {
		errno = ENOTTY;
		return 0;
	}
	if (fcntl (input, F_SETFD, FD_CLOEXEC) == -1) {
		msg_warn ("fcntl failed: %d, '%s'", errno, strerror (errno));
	}

	/* Turn echo off */
	if (tcgetattr (input, &oterm) != 0) {
		errno = ENOTTY;
		return 0;
	}
	memcpy (&term, &oterm, sizeof(term));
	term.c_lflag &= ~(ECHO | ECHONL);
	(void)tcsetattr (input, TCSAFLUSH, &term);
	(void)write (output, "Enter passphrase: ", sizeof ("Enter passphrase: ") -
		1);

	/* Save the current sighandler */
	for (i = 0; i < NSIG; i++) {
		saved_signo[i] = 0;
	}
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = read_pass_tmp_sig_handler;
	(void)sigaction (SIGALRM, &sa, &savealrm);
	(void)sigaction (SIGHUP, &sa, &savehup);
	(void)sigaction (SIGINT, &sa, &saveint);
	(void)sigaction (SIGPIPE, &sa, &savepipe);
	(void)sigaction (SIGQUIT, &sa, &savequit);
	(void)sigaction (SIGTERM, &sa, &saveterm);
	(void)sigaction (SIGTSTP, &sa, &savetstp);
	(void)sigaction (SIGTTIN, &sa, &savettin);
	(void)sigaction (SIGTTOU, &sa, &savettou);

	/* Now read a passphrase */
	p = buf;
	end = p + size - 1;
	while (read (input, &ch, 1) == 1 && ch != '\n' && ch != '\r') {
		if (p < end) {
			*p++ = ch;
		}
	}
	*p = '\0';
	(void)write (output, "\n", 1);

	/* Restore terminal state */
	if (memcmp (&term, &oterm, sizeof (term)) != 0) {
		while (tcsetattr (input, TCSAFLUSH, &oterm) == -1 &&
			errno == EINTR && !saved_signo[SIGTTOU]) ;
	}

	/* Restore signal handlers */
	(void)sigaction (SIGALRM, &savealrm, NULL);
	(void)sigaction (SIGHUP, &savehup, NULL);
	(void)sigaction (SIGINT, &saveint, NULL);
	(void)sigaction (SIGQUIT, &savequit, NULL);
	(void)sigaction (SIGPIPE, &savepipe, NULL);
	(void)sigaction (SIGTERM, &saveterm, NULL);
	(void)sigaction (SIGTSTP, &savetstp, NULL);
	(void)sigaction (SIGTTIN, &savettin, NULL);
	(void)sigaction (SIGTTOU, &savettou, NULL);

	close (input);

	/* Send signals pending */
	for (i = 0; i < NSIG; i++) {
		if (saved_signo[i]) {
			kill (getpid (), i);
			switch (i) {
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				goto restart;
			}
		}
	}

	return p - buf;
#endif
}

/*
 * GString ucl emitting functions
 */
static int
rspamd_gstring_append_character (unsigned char c, size_t len, void *ud)
{
	GString *buf = ud;
	gsize old_len;

	if (len == 1) {
		g_string_append_c (buf, c);
	}
	else {
		if (buf->allocated_len - buf->len <= len) {
			old_len = buf->len;
			g_string_set_size (buf, buf->len + len + 1);
			buf->len = old_len;
		}
		memset (&buf->str[buf->len], c, len);
		buf->len += len;
	}

	return 0;
}

static int
rspamd_gstring_append_len (const unsigned char *str, size_t len, void *ud)
{
	GString *buf = ud;

	g_string_append_len (buf, str, len);

	return 0;
}

static int
rspamd_gstring_append_int (int64_t val, void *ud)
{
	GString *buf = ud;

	rspamd_printf_gstring (buf, "%L", (intmax_t)val);
	return 0;
}

static int
rspamd_gstring_append_double (double val, void *ud)
{
	GString *buf = ud;
	const double delta = 0.0000001;

	if (val == (double)(int)val) {
		rspamd_printf_gstring (buf, "%.1f", val);
	}
	else if (fabs (val - (double)(int)val) < delta) {
		/* Write at maximum precision */
		rspamd_printf_gstring (buf, "%.*g", DBL_DIG, val);
	}
	else {
		rspamd_printf_gstring (buf, "%f", val);
	}

	return 0;
}

void
rspamd_ucl_emit_gstring (ucl_object_t *obj,
	enum ucl_emitter emit_type,
	GString *target)
{
	struct ucl_emitter_functions func = {
		.ucl_emitter_append_character = rspamd_gstring_append_character,
		.ucl_emitter_append_len = rspamd_gstring_append_len,
		.ucl_emitter_append_int = rspamd_gstring_append_int,
		.ucl_emitter_append_double = rspamd_gstring_append_double
	};

	func.ud = target;
	ucl_object_emit_full (obj, emit_type, &func);
}

/*
 * We use here z-base32 encoding described here:
 * http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 */

gchar *
rspamd_encode_base32 (const guchar *in, gsize inlen)
{
	gint remain = -1, x;
	gsize i, r;
	gsize allocated_len = inlen * 8 / 5 + 2;
	gchar *out;
	static const char b32[]="ybndrfg8ejkmcpqxot1uwisza345h769";

	out = g_malloc (allocated_len);
	for (i = 0, r = 0; i < inlen; i++) {
		switch (i % 5) {
		case 0:
			/* 8 bits of input and 3 to remain */
			x = in[i];
			remain = in[i] >> 5;
			out[r++] = b32[x & 0x1F];
			break;
		case 1:
			/* 11 bits of input, 1 to remain */
			x = remain | in[i] << 3;
			out[r++] = b32[x & 0x1F];
			out[r++] = b32[x >> 5 & 0x1F];
			remain = x >> 10;
			break;
		case 2:
			/* 9 bits of input, 4 to remain */
			x = remain | in[i] << 1;
			out[r++] = b32[x & 0x1F];
			remain = x >> 5;
			break;
		case 3:
			/* 12 bits of input, 2 to remain */
			x = remain | in[i] << 4;
			out[r++] = b32[x & 0x1F];
			out[r++] = b32[x >> 5 & 0x1F];
			remain = x >> 10 & 0x3;
			break;
		case 4:
			/* 10 bits of output, nothing to remain */
			x = remain | in[i] << 2;
			out[r++] = b32[x & 0x1F];
			out[r++] = b32[x >> 5 & 0x1F];
			remain = -1;
			break;
		default:
			/* Not to be happen */
			break;
		}

	}
	if (remain >= 0) {
		out[r++] = b32[remain];
	}

	out[r] = 0;
	g_assert (r < allocated_len);

	return out;
}

static const guchar b32_dec[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x12, 0xff, 0x19, 0x1a, 0x1b, 0x1e, 0x1d,
	0x07, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x18, 0x01, 0x0c, 0x03, 0x08, 0x05, 0x06,
	0x1c, 0x15, 0x09, 0x0a, 0xff, 0x0b, 0x02, 0x10,
	0x0d, 0x0e, 0x04, 0x16, 0x11, 0x13, 0xff, 0x14,
	0x0f, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x18, 0x01, 0x0c, 0x03, 0x08, 0x05, 0x06,
	0x1c, 0x15, 0x09, 0x0a, 0xff, 0x0b, 0x02, 0x10,
	0x0d, 0x0e, 0x04, 0x16, 0x11, 0x13, 0xff, 0x14,
	0x0f, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

guchar*
rspamd_decode_base32 (const gchar *in, gsize inlen, gsize *outlen)
{
	guchar *res, decoded;
	guchar c;
	guint acc = 0U;
	guint processed_bits = 0;
	gsize olen = 0, i, allocated_len = inlen * 5 / 8 + 2;

	res = g_malloc (allocated_len);

	for (i = 0; i < inlen; i ++) {
		c = (guchar)in[i];

		if (processed_bits >= 8) {
			processed_bits -= 8;
			res[olen++] = acc & 0xFF;
			acc >>= 8;
		}

		decoded = b32_dec[c];
		if (decoded == 0xff) {
			g_free (res);
			return NULL;
		}

		acc = (decoded << processed_bits) | acc;
		processed_bits += 5;
	}

	if (processed_bits > 0) {
		res[olen++] = (acc & 0xFF);
	}

	g_assert (olen <= allocated_len);

	*outlen = olen;

	return res;
}


gchar *
rspamd_encode_base64 (const guchar *in, gsize inlen, gint str_len, gsize *outlen)
{
#define CHECK_SPLIT \
	do { if (str_len > 0 && cols >= str_len) { \
				*o++ = '\r'; \
				*o++ = '\n'; \
				cols = 0; \
	} } \
while (0)

	gsize allocated_len = (inlen / 3) * 4 + 4;
	gchar *out, *o;
	guint64 n;
	guint32 rem, t, carry;
	gint cols, shift;
	static const char b64_enc[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	if (str_len > 0) {
		g_assert (str_len > 8);
		allocated_len += (allocated_len / str_len + 1) * 2 + 1;
	}

	out = g_malloc (allocated_len);
	o = out;
	cols = 0;

	while (inlen > 6) {
		n = *(guint64 *)in;
		n = GUINT64_TO_BE (n);

		if (str_len <= 0 || cols <= str_len - 8) {
			*o++ = b64_enc[(n >> 58) & 0x3F];
			*o++ = b64_enc[(n >> 52) & 0x3F];
			*o++ = b64_enc[(n >> 46) & 0x3F];
			*o++ = b64_enc[(n >> 40) & 0x3F];
			*o++ = b64_enc[(n >> 34) & 0x3F];
			*o++ = b64_enc[(n >> 28) & 0x3F];
			*o++ = b64_enc[(n >> 22) & 0x3F];
			*o++ = b64_enc[(n >> 16) & 0x3F];
			cols += 8;
		}
		else {
			cols = str_len - cols;
			shift = 58;
			while (cols) {
				*o++ = b64_enc[(n >> shift) & 0x3F];
				shift -= 6;
				cols --;
			}

			*o++ = '\r';
			*o++ = '\n';

			/* Remaining bytes */
			while (shift >= 16) {
				*o++ = b64_enc[(n >> shift) & 0x3F];
				shift -= 6;
				cols ++;
			}
		}

		in += 6;
		inlen -= 6;
	}

	CHECK_SPLIT;

	rem = 0;
	carry = 0;

	for (;;) {
		/* Padding + remaining data (0 - 2 bytes) */
		switch (rem) {
		case 0:
			if (inlen-- == 0) {
				goto end;
			}
			t = *in++;
			*o++ = b64_enc[t >> 2];
			carry = (t << 4) & 0x30;
			rem = 1;
			cols ++;
		case 1:
			if (inlen-- == 0) {
				goto end;
			}
			CHECK_SPLIT;
			t = *in++;
			*o++ = b64_enc[carry | (t >> 4)];
			carry = (t << 2) & 0x3C;
			rem = 2;
			cols ++;
		default:
			if (inlen-- == 0) {
				goto end;
			}
			CHECK_SPLIT;
			t = *in ++;
			*o++ = b64_enc[carry | (t >> 6)];
			cols ++;
			CHECK_SPLIT;
			*o++ = b64_enc[t & 0x3F];
			cols ++;
			CHECK_SPLIT;
			rem = 0;
		}
	}

end:
	if (rem == 1) {
		*o++ = b64_enc[carry];
		cols ++;
		CHECK_SPLIT;
		*o++ = '=';
		cols ++;
		CHECK_SPLIT;
		*o++ = '=';
		cols ++;
		CHECK_SPLIT;
	}
	else if (rem == 2) {
		*o++ = b64_enc[carry];
		cols ++;
		CHECK_SPLIT;
		*o++ = '=';
		cols ++;
	}

	CHECK_SPLIT;

	*o = '\0';

	if (outlen != NULL) {
		*outlen = o - out;
	}

	return out;
}

gdouble
rspamd_get_ticks (void)
{
	gdouble res;

#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
	clock_gettime (CLOCK_MONOTONIC, &ts);

	res = (double)ts.tv_sec + ts.tv_nsec / 1000000000.;
#elif defined(__APPLE__)
	res = mach_absolute_time () / 1000000000.;
#else
	struct timeval tv;

	(void)gettimeofday (&tv, NULL);
	res = (double)tv.tv_sec + tv.tv_nsec / 1000000.;
#endif

	return res;
}

gdouble
rspamd_get_virtual_ticks (void)
{
	gdouble res;

#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;
# ifdef CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
# elif defined(CLOCK_PROF)
	clock_gettime (CLOCK_PROF, &ts);
# elif defined(CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &ts);
# else
	clock_gettime (CLOCK_REALTIME, &ts);
# endif

	res = (double)ts.tv_sec + ts.tv_nsec / 1000000000.;
#else
	res = clock () / (double)CLOCKS_PER_SEC;
#endif

	return res;
}

/* Required for tweetnacl */
void
randombytes (guchar *buf, guint64 len)
{
	ottery_rand_bytes (buf, (size_t)len);
}


void
rspamd_ptr_array_free_hard (gpointer p)
{
	GPtrArray *ar = (GPtrArray *)p;

	g_ptr_array_free (ar, TRUE);
}

void
rspamd_array_free_hard (gpointer p)
{
	GArray *ar = (GArray *)p;

	g_array_free (ar, TRUE);
}

void
rspamd_gstring_free_hard (gpointer p)
{
	GString *ar = (GString *)p;

	g_string_free (ar, TRUE);
}


void
rspamd_init_libs (void)
{
	struct rlimit rlim;

	ottery_init (NULL);

	rspamd_cryptobox_init ();
#ifdef HAVE_SETLOCALE
	/* Set locale setting to C locale to avoid problems in future */
	setlocale (LC_ALL, "C");
	setlocale (LC_CTYPE, "C");
	setlocale (LC_MESSAGES, "C");
	setlocale (LC_TIME, "C");
#endif

#ifdef HAVE_OPENSSL
	ERR_load_crypto_strings ();

	OpenSSL_add_all_algorithms ();
	OpenSSL_add_all_digests ();
	OpenSSL_add_all_ciphers ();
#endif
	g_random_set_seed (ottery_rand_uint32 ());

	/* Set stack size for pcre */
	getrlimit (RLIMIT_STACK, &rlim);
	rlim.rlim_cur = 100 * 1024 * 1024;
	setrlimit (RLIMIT_STACK, &rlim);

	event_init ();
#ifdef GMIME_ENABLE_RFC2047_WORKAROUNDS
	g_mime_init (GMIME_ENABLE_RFC2047_WORKAROUNDS);
#else
	g_mime_init (0);
#endif
}

guint64
rspamd_hash_seed (void)
{
	static guint64 seed;

	if (seed == 0) {
		seed = ottery_rand_uint64 ();
	}

	return seed;
}

gdouble
rspamd_time_jitter (gdouble in, gdouble jitter)
{
	guint64 rnd_int;
	double res;
	const double transform_bias = 2.2204460492503130808472633361816e-16;

	rnd_int = ottery_rand_uint64 () >> 12;
	res = rnd_int;
	res *= transform_bias;

	if (jitter == 0) {
		jitter = in;
	}

	return in + jitter * res;
}
