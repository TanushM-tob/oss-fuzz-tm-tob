/*
 * Copyright (C) 2013-2014 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __LEXER_H_
#define __LEXER_H_

#include "ast.h"

// Token definitions for JSONPath parser
#define T_AND        1
#define T_OR         2
#define T_UNION      3
#define T_EQ         4
#define T_NE         5
#define T_GT         6
#define T_GE         7
#define T_LT         8
#define T_LE         9
#define T_MATCH      10
#define T_NOT        11
#define T_LABEL      12
#define T_ROOT       13
#define T_THIS       14
#define T_DOT        15
#define T_WILDCARD   16
#define T_REGEXP     17
#define T_BROPEN     18
#define T_BRCLOSE    19
#define T_BOOL       20
#define T_NUMBER     21
#define T_STRING     22
#define T_POPEN      23
#define T_PCLOSE     24

extern const char *tokennames[25];

struct jp_opcode *
jp_get_token(struct jp_state *s, const char *input, int *mlen);

#endif /* __LEXER_H_ */
