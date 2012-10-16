#ifndef _LTTNG_TRACEPOINT_TYPES_H
#define _LTTNG_TRACEPOINT_TYPES_H

/*
 * Copyright 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

struct tracepoint_probe {
	void (*func)(void);
	void *data;
};

#define TRACEPOINT_PADDING	16
struct tracepoint {
	const char *name;
	int state;
	struct tracepoint_probe *probes;
	int *tracepoint_provider_ref;
	const char *signature;
	char padding[TRACEPOINT_PADDING];
};

#define TRACEPOINT_CALLSITE_PADDING	16
struct tracepoint_callsite {
	const char *name;
	const char *func;
	const char *file;
	void *ip;
	unsigned int lineno;
	char padding[TRACEPOINT_CALLSITE_PADDING];
} __attribute__((packed));

#endif /* _LTTNG_TRACEPOINT_TYPES_H */
