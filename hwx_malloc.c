#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "xmalloc.h"

typedef struct hm_stats {
  long pages_mapped;
  long pages_unmapped;
  long chunks_allocated;
  long chunks_freed;
  long free_length;
} hm_stats;

typedef struct free_cell {
    size_t size;
    struct free_cell *next;
} free_cell;

static free_cell *list;
const size_t PAGE_SIZE = 4096;
static hm_stats stats; // This initializes the stats to 0.
pthread_mutex_t mutex;
int lock_init = 0;

long
free_list_length()
{
    // TODO: Calculate the length of the free list
    long len = 0;
    free_cell *node = list;
    while (node != 0) {
        len += 1;
        node = node->next;
    }
    return len;
}

hm_stats*
hgetstats()
{
    stats.free_length = free_list_length();
    return &stats;
}

void
hprintstats()
{
    stats.free_length = free_list_length();
    fprintf(stderr, "\n== husky malloc stats ==\n");
    fprintf(stderr, "Mapped:   %ld\n", stats.pages_mapped);
    fprintf(stderr, "Unmapped: %ld\n", stats.pages_unmapped);
    fprintf(stderr, "Allocs:   %ld\n", stats.chunks_allocated);
    fprintf(stderr, "Frees:    %ld\n", stats.chunks_freed);
    fprintf(stderr, "Freelen:  %ld\n", stats.free_length);
}

static
size_t
div_up(size_t xx, size_t yy)
{
    // This is useful to calculate # of pages
    // for large allocations.
    size_t zz = xx / yy;

    if (zz * yy == xx) {
        return zz;
    }
    else {
        return zz + 1;
    }
}

void 
coalesce(free_cell *cell)
{
    if (list == 0)
    {
        list = cell;
        return;
    }

    free_cell *prev_node = 0;
    free_cell *node = list;

    while (node != 0)
    {
        if ((void *)cell < (void *)node)
        {
            size_t size_prev = 0;

            if (prev_node != 0)
            {
                size_prev = prev_node->size;
            }

            if (cell->size + (void *)cell == (void *)node && size_prev + (void *)prev_node == (void *)cell)
            {
                //3 in a row free
                prev_node->size = node->size + cell->size + prev_node->size;
                prev_node->next = node->next;
            } 
            else if ((void *)node == (void *)cell + cell->size)
            {
                cell->size = node->size + cell->size;

                if (prev_node != 0)
                {
                    prev_node->next = cell;
                }

                cell->next = node->next;
            }
            else if ((void *)cell == size_prev + (void *) prev_node)
            {
                prev_node->size = prev_node->size + cell->size;
            }
            else {
                if (prev_node != 0) {
                    prev_node->next = cell;
                }

                cell->next = node;
            }

            if (prev_node == 0)
            {
                list = cell;
            }

            break;
        }

        prev_node = node;
        node = node->next;
    }
}

void*
xmalloc(size_t size)
{
    if (!lock_init) {
        pthread_mutex_init(&mutex, 0);
        lock_init = 1;
    }
    stats.chunks_allocated += 1;
    size += sizeof(size_t);

    // TODO: Actually allocate memory with mmap and a free list.
    if (size < PAGE_SIZE) {
        pthread_mutex_lock(&mutex);
        free_cell *mem_block = 0;
        free_cell *prev_node = 0;
        free_cell *node = list;

        while (node != 0) {
            if (node->size >= size) {
                mem_block = node;
                
                if (prev_node == 0) {
                    list = node->next;                    
                } else {
                    prev_node->next = node->next;
                }

                break;
            }

            prev_node = node;
            node = node->next;
        }

        //mmap if no block in free list big enough
        if (mem_block == 0) {
            mem_block = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert(mem_block != MAP_FAILED);    
            mem_block->size = PAGE_SIZE;
            stats.pages_mapped += 1;
        } 
        
        if (mem_block->size - size >= sizeof(free_cell)) {
            //if big enough, allocate part of the block for usage
            void *address = size + (void *)mem_block;
            free_cell *free_mem = (free_cell *)address;
            free_mem->size = mem_block->size - size;

            //coalesce free memory to adjacent free memory blocks
            coalesce(free_mem);
            
            mem_block->size = size;
        }

        pthread_mutex_unlock(&mutex);
        return (void *)mem_block + sizeof(size_t);
    } else {
        int amt = div_up(size, PAGE_SIZE);
        size_t total_size = PAGE_SIZE * amt;
        free_cell *mem_block = mmap(0, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(mem_block != MAP_FAILED);

        mem_block->size = total_size;
        stats.pages_mapped += amt;
        return (void *)mem_block + sizeof(size_t);
    }

    //return (void*) 0xDEADBEEF;
}

void
xfree(void* item)
{
    stats.chunks_freed += 1;

    // TODO: Actually free the item.
    free_cell *mem_block = (free_cell *)(item - sizeof(size_t));

    if (mem_block->size < PAGE_SIZE) {
        pthread_mutex_lock(&mutex);
        coalesce(mem_block);
        pthread_mutex_unlock(&mutex);
    } else {
        int amt = div_up(mem_block->size, PAGE_SIZE);
        int rv = munmap((void *)mem_block, mem_block->size);
        assert(rv != -1);
        stats.pages_unmapped += amt;
    }
}

void* 
xrealloc(void* ptr, size_t size)
{
	if (ptr == NULL) {
		return xmalloc(size);
	}
	void* base = ptr - sizeof(size_t);
	size_t* base_size = base;
	if (*base_size > size) {
		int leftover = size - *base_size;
        //leftover can store header
		if (leftover >= sizeof(free_cell)) {
			pthread_mutex_lock(&mutex);
			base += *base_size;
			free_cell* cell = (free_cell*)base;
			cell->size = leftover;
			if (list != 0) {
				free_cell* head = list;
				while(head->next) {
					head = head->next;
				}
				head->next = cell;
			} else {
			    list = cell;
			}
			pthread_mutex_unlock(&mutex);
			*base_size = size;
			return ptr;
		}
	} else if (*base_size == size) {
		return ptr;
	} else {
		void* base = ptr - sizeof(size_t);
		size_t* base_size = base;
		void* new_ptr = xmalloc(size);
		memcpy(new_ptr, ptr, *base_size);
		xfree(ptr);
		return new_ptr;
	}
	return 0;
}
