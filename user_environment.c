/*-
 * Copyright (c) 2009-2010 Brad Penoff
 * Copyright (c) 2009-2010 Humaira Kamal
 * Copyright (c) 2011-2012 Irene Ruengeler
 * Copyright (c) 2011-2012 Michael Tuexen
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* __Userspace__ */

#include <stdlib.h>
#if !defined (__Userspace_os_Windows)
#include <stdint.h>
#include <netinet/sctp_os_userspace.h>
#endif
#include <user_environment.h>
#include <sys/types.h>
/* #include <sys/param.h> defines MIN */
#if !defined(MIN)
#define MIN(arg1,arg2) ((arg1) < (arg2) ? (arg1) : (arg2))
#endif
#include <string.h>

#define uHZ 1000

/* See user_include/user_environment.h for comments about these variables */
int maxsockets = 25600;
int hz = uHZ;
int ip_defttl = 64;
int ipport_firstauto = 49152, ipport_lastauto = 65535;
int nmbclusters = 65536;

/* Source ip_output.c. extern'd in ip_var.h */
u_short ip_id = 0; /*__Userspace__ TODO Should it be initialized to zero? */

/* used in user_include/user_atomic.h in order to make the operations
 * defined there truly atomic
 */
userland_mutex_t atomic_mtx;

/* Source: /usr/src/sys/dev/random/harvest.c */
static int read_random_phony(void *, int);

static int (*read_func)(void *, int) = read_random_phony;

/* Userland-visible version of read_random */
int
read_random(void *buf, int count)
{
	return ((*read_func)(buf, count));
}

/* If the entropy device is not loaded, make a token effort to
 * provide _some_ kind of randomness. This should only be used
 * inside other RNG's, like arc4random(9).
 */
static int
read_random_phony(void *buf, int count)
{
	uint32_t randval;
	int size, i;

	/* srandom() is called in kern/init_main.c:proc0_post() */

	/* Fill buf[] with random(9) output */
	for (i = 0; i < count; i+= (int)sizeof(uint32_t)) {
		randval = random();
		size = MIN(count - i, (int)sizeof(uint32_t));
		memcpy(&((char *)buf)[i], &randval, (size_t)size);
	}

	return (count);
}

void usrsctp_wsa_sync_last_error(void)
{
#ifdef _WIN32
	int iError = 0;

	switch (errno)
	{
		/* Base error codes */

		case EINTR:
			iError = WSAEINTR;
			break;
		case EBADF:
			iError = WSAEBADF;
			break;
		case EACCES:
			iError = WSAEACCES;
			break;
		case EFAULT:
			iError = WSAEFAULT;
			break;
		case EINVAL:
			iError = WSAEINVAL;
			break;
		case EMFILE:
			iError = WSAEMFILE;
			break;

		/* BSD sockets error codes */

		case EWOULDBLOCK:
			iError = WSAEWOULDBLOCK;
			break;
		case EINPROGRESS:
			iError = WSAEINPROGRESS;
			break;
		case EALREADY:
			iError = WSAEALREADY;
			break;
		case ENOTSOCK:
			iError = WSAENOTSOCK;
			break;
		case EDESTADDRREQ:
			iError = WSAEDESTADDRREQ;
			break;
		case EMSGSIZE:
			iError = WSAEMSGSIZE;
			break;
		case EPROTOTYPE:
			iError = WSAEPROTOTYPE;
			break;
		case ENOPROTOOPT:
			iError = WSAENOPROTOOPT;
			break;
		case EPROTONOSUPPORT:
			iError = WSAEPROTONOSUPPORT;
			break;
		case ESOCKTNOSUPPORT:
			iError = WSAESOCKTNOSUPPORT;
			break;
		case EOPNOTSUPP:
			iError = WSAEOPNOTSUPP;
			break;
		case EPFNOSUPPORT:
			iError = WSAEPFNOSUPPORT;
			break;
		case EAFNOSUPPORT:
			iError = WSAEAFNOSUPPORT;
			break;
		case EADDRINUSE:
			iError = WSAEADDRINUSE;
			break;
		case EADDRNOTAVAIL:
			iError = WSAEADDRNOTAVAIL;
			break;
		case ENETDOWN:
			iError = WSAENETDOWN;
			break;
		case ENETUNREACH:
			iError = WSAENETUNREACH;
			break;
		case ENETRESET:
			iError = WSAENETRESET;
			break;
		case ECONNABORTED:
			iError = WSAECONNABORTED;
			break;
		case ECONNRESET:
			iError = WSAECONNRESET;
			break;
		case ENOBUFS:
			iError = WSAENOBUFS;
			break;
		case EISCONN:
			iError = WSAEISCONN;
			break;
		case ENOTCONN:
			iError = WSAENOTCONN;
			break;
		case ESHUTDOWN:
			iError = WSAESHUTDOWN;
			break;
		case ETOOMANYREFS:
			iError = WSAETOOMANYREFS;
			break;
		case ETIMEDOUT:
			iError = WSAETIMEDOUT;
			break;
		case ECONNREFUSED:
			iError = WSAECONNREFUSED;
			break;
		case ELOOP:
			iError = WSAELOOP;
			break;
		case ENAMETOOLONG:
			iError = WSAENAMETOOLONG;
			break;
		case EHOSTDOWN:
			iError = WSAEHOSTDOWN;
			break;
		case EHOSTUNREACH:
			iError = WSAEHOSTUNREACH;
			break;
		case ENOTEMPTY:
			iError = WSAENOTEMPTY;
			break;
#ifdef EPROCLIM
		case EPROCLIM:
			iError = WSAEPROCLIM;
			break;
#endif
		case EUSERS:
			iError = WSAEUSERS;
			break;
		case EDQUOT:
			iError = WSAEDQUOT;
			break;
		case ESTALE:
			iError = WSAESTALE;
			break;
		case EREMOTE:
			iError = WSAEREMOTE;
			break;

		/* Special cases */

#if (EAGAIN != EWOULDBLOCK)
		case EAGAIN:
			iError = WSAEWOULDBLOCK;
			break;
#endif

#if defined(EPROTO)
		case EPROTO:
			iError = WSAECONNRESET;
			break;
#endif
	}

	/**
	* Windows Sockets Extended Error Codes:
	*
	* WSASYSNOTREADY
	* WSAVERNOTSUPPORTED
	* WSANOTINITIALISED
	* WSAEDISCON
	* WSAENOMORE
	* WSAECANCELLED
	* WSAEINVALIDPROCTABLE
	* WSAEINVALIDPROVIDER
	* WSAEPROVIDERFAILEDINIT
	* WSASYSCALLFAILURE
	* WSASERVICE_NOT_FOUND
	* WSATYPE_NOT_FOUND
	* WSA_E_NO_MORE
	* WSA_E_CANCELLED
	* WSAEREFUSED
	*/

	WSASetLastError(iError);
#endif
}
