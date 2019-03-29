#ifndef __STDAFX_H__
#define __STDAFX_H__

#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <../../debug_core/debug_core/include/debug_core.h>
#include <../../conversion_core/conversion_core/include/conversion_core.h>

typedef enum {
	FALSE, TRUE
} BOOL;

#endif //__STDAFX_H__
