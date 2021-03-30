#ifndef XMALLOC_H
#define XMALLOC_H

#include <stddef.h>

void* xmalloc(size_t size);
void  xfree(void* item);
void* xrealloc(void* item, size_t size);

#endif
