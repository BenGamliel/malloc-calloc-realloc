#include <stdlib.h>
#include <unistd.h>

#define MIN_SIZE 0
#define MAX_SIZE 100000000

void* malloc(size_t size) {
   void* addr;
   if (size <= MIN_SIZE || size > MAX_SIZE)
      return NULL;
   addr = sbrk(size);
   if (addr == (void*)(-1))
      return NULL;
   return addr;
}
