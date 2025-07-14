/*****************************************************************************
  Copyright (c) 2006 EMC Corporation.
  Copyright (c) 2011 Factor-SPE

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the Free
  Software Foundation; either version 2 of the License, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.

  The full GNU General Public License is included in this distribution in the
  file called LICENSE.

  Authors: Srinivas Aji <Aji_Srinivas@emc.com>
  Authors: Vitalii Demianets <dvitasgs@gmail.com>

******************************************************************************/

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

#define LOG_LEVEL_NONE  0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_STATE_MACHINE_TRANSITION 4

#ifdef DEBUG
#define LOG_LEVEL_MAX   100
#else
#define LOG_LEVEL_MAX	LOG_LEVEL_INFO
#endif

#define LOG_LEVEL_DEFAULT LOG_LEVEL_ERROR

extern void Dprintf(int level, const char *fmt, ...);
extern int log_level;

#define PRINT(_level, _fmt, _args...)			\
	({						\
		/* Disabled for fuzzing */		\
	})

#define TSTM(x, y, _fmt, _args...)                                         \
    do if(!(x))                                                            \
    {                                                                      \
        /* Error logging disabled for fuzzing */                          \
        return y;                                                          \
    } while (0)

#define TST(x, y) TSTM(x, y, "")

#define LOG(_fmt, _args...) \
    /* Disabled for fuzzing */

#define INFO(_fmt, _args...) \
    /* Disabled for fuzzing */

#define ERROR(_fmt, _args...) \
    /* Disabled for fuzzing */

static inline void dump_hex(void *b, int l)
{
    /* Disabled for fuzzing */
    (void)b;
    (void)l;
}

#endif /* LOG_H */
