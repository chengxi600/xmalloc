#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "xmalloc.h"

#define PAGE_SIZE 4096
#define BUCKET_COUNT 16

const int bucket_sizes[BUCKET_COUNT] = {16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072};
__thread void* buckets[BUCKET_COUNT] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
__thread void** free_list[BUCKET_COUNT] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int
get_bucket_num(size_t size)
{
	for(int i = 0; i < BUCKET_COUNT; ++i)
	{
		if(size <= bucket_sizes[i])
			return i;
	}
	return -1;
}

void
insert_ptr(void* ptr, size_t remaining)
{
	int bucket_num = get_bucket_num(remaining) - 1;
    if(bucket_num >= 0) {
	    int bucket_size = bucket_sizes[bucket_num];
	    *((void**)ptr) = (void*)free_list[bucket_num];
	    free_list[bucket_num] = (void**)ptr;
	    insert_ptr(ptr + bucket_size, remaining - bucket_size);
    }
}

void*
xmalloc(size_t size)
{
	size += sizeof(size_t);

	int bucket_num = get_bucket_num(size);
	int bucket_size = bucket_sizes[bucket_num];
	if(bucket_num < 0) //> 1 page
	{
		size = (size / PAGE_SIZE + ((size % PAGE_SIZE) ? 1 : 0)) * PAGE_SIZE;
        size_t* ptr = (size_t*)mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		*ptr = size;
		return ptr + 1;
	}
	else if(free_list[bucket_num]) //have bucket on free_list
	{
		void** bucket = free_list[bucket_num];
		free_list[bucket_num] = (void**)(*bucket);
		size_t* ptr = (size_t*)bucket;
		*ptr = bucket_num;
		return ptr + 1;
	}
	else //no bucket on free list
	{
		for(int i = bucket_num + 1; i < BUCKET_COUNT; ++i)
		{
			if(free_list[i]) 
			{
				void** bucket = free_list[i];
				free_list[i] = (void**)(*bucket);
				size_t* ptr = (size_t*)bucket;
				*ptr = bucket_num;
				insert_ptr((void*)bucket + bucket_size, bucket_sizes[i] - bucket_size);
				return ptr + 1;
			}
		}

        //create bucket
		void* new_page = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		void* prev = 0;
		void* page = buckets[bucket_num];
		while(page)
		{
			prev = page;
			page = *((void**)page);
		}
		if(!prev)
			buckets[bucket_num] = new_page;
		else
			*((void**)prev) = new_page;

		*((void**)new_page) = 0;
		size_t* ptr = new_page + sizeof(void*);
		*ptr = bucket_num;
		
		int buckets = (PAGE_SIZE - sizeof(void*)) / bucket_size - 1;
		void** working = (void**)((void*)ptr + bucket_size);
		for(int i = 0; i < buckets; ++i, working = (void**)((void*)working + bucket_size))
		{
			*working = free_list[bucket_num];
			free_list[bucket_num] = working;
		}
		insert_ptr((void*)working, PAGE_SIZE - (buckets + 1) * bucket_size - sizeof(void*));
		return (ptr + 1);
	}
}

void
xfree(void* ptr)
{
	int id = *((size_t*)(ptr - sizeof(size_t)));
	if(id >= BUCKET_COUNT)
		munmap(ptr - sizeof(size_t), id);
	else
	{
		void** base = (void**)(ptr - sizeof(size_t));
		*base = free_list[id];
		free_list[id] = base;
	}
}

void*
xrealloc(void* ptr, size_t size)
{
	void* new_ptr = xmalloc(size);
	memcpy(new_ptr, ptr, size);
	xfree(ptr);
	return new_ptr;
}

