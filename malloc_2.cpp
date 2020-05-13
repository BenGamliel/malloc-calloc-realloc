#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>


#define MIN_SIZE 0
#define MAX_SIZE 100000000


class AllocationData {
public:

    void set_is_free(bool free) {
        _is_free = free;
    }

    void set_original_size(size_t size) {
        _original_size = size;
    }

    void set_requested_size(size_t size) {
        _requested_size = size;
    }

    void set_allocation_addr(void *addr) {
        _allocation_addr = addr;
    }

    void set_next(AllocationData* next) {
        _next = next;
    }

    void set_prev(AllocationData* prev) {
        _prev = prev;
    }

    bool is_free() {
        return _is_free;
    }

    size_t get_original_size() {
        return _original_size;
    }

    size_t get_requested_size() {
        return _requested_size;
    }

    void* get_allocation_addr() {
        return _allocation_addr;
    }

    AllocationData* get_next() {
        return _next;
    }

    AllocationData* get_prev() {
        return _prev;
    }

private:
    bool _is_free;
    size_t _original_size;
    size_t _requested_size;
    void* _allocation_addr;
    AllocationData* _next;
    AllocationData* _prev;
};

size_t _num_free_blocks();
size_t _num_free_bytes();
size_t _num_allocated_blocks();
size_t _num_allocated_bytes();
size_t _num_meta_data_bytes();
size_t _size_meta_data();



AllocationData* allocHistory = NULL;

void* smalloc(size_t size) {
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }

    AllocationData* metaData = NULL;
    AllocationData* it = NULL;

    // First, we search for freed space in our global list
    if (allocHistory) {
        for (it = allocHistory; it; it = it->get_next()) {
            if (it->get_original_size() >= size && it->is_free()) {
                metaData = it;
                break;
            }
        }

        if (metaData) {
            metaData->set_is_free(false);
            metaData->set_requested_size(size);
            return metaData->get_allocation_addr();
        }
    }

    // Not enough freed space was found, so we allocate new space
    // Allocating metaData
    metaData = (AllocationData*)sbrk(sizeof(AllocationData));
    if (metaData == (void*)(-1)) {
        return NULL;
    }

    // Allocating requested_size bytes
    void* allocation_addr = sbrk(size);
    if (allocation_addr == (void*)(-1)) {
        sbrk(-sizeof(AllocationData));
        return NULL;
    }

    // Setting up the meta data
    metaData->set_is_free(false);
    metaData->set_original_size(size);
    metaData->set_requested_size(size);
    metaData->set_allocation_addr(allocation_addr);
    metaData->set_next(NULL);
    metaData->set_prev(NULL);

    // Adding the allocation meta-data to the allocation history list
    // For the first allocation
    if (!allocHistory) {
        allocHistory = metaData;
    }
    else {
        // In case there are others, we need to find the last allocation made
        it = allocHistory;
        while (it->get_next()) {
            it = it->get_next();
        }
        metaData->set_prev(it);
        it->set_next(metaData);
    }

    return allocation_addr;
}


void* scalloc(size_t num, size_t size) {
    // First, we allocate a new space (possibly reused allocation)
    void* allocation_addr = smalloc(num * size);
    if (!allocation_addr) {
        return NULL;
    }
    else {
        // If we succeed in allocating, we clear the block
        return std::memset(allocation_addr, 0, num * size);
    }
}

void sfree(void* p) {
    if (!p) {
        return;
    }

    // We search for p in our global list
    for (AllocationData* it = allocHistory; it; it = it->get_next()) {
        if (it->get_allocation_addr() == p) {
            // If 'p' was already released, we ignore the action
            if (it->is_free()) {
                return;
            }
                // If not, we free the allocated block
            else {
                it->set_is_free(true);
                return;
            }
        }
    }

}


void* srealloc(void* oldp, size_t size) {
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }

    // If oldp is NULL, we allocate space for 'size' bytes and return a poiter to it
    if (!oldp) {
        void* allocation_addr = smalloc(size);
        if (!allocation_addr) {
            return NULL;
        }
        else {
            return allocation_addr;
        }
    }

    // If not, we search for it assuming oldp is a pointer to a previously allocated block
    AllocationData* metaData = NULL;
    for (AllocationData* it = allocHistory; it; it = it->get_next()) {
        if (it->get_allocation_addr() == oldp) {
            metaData = it;
            break;
        }
    }

    // We determine whether allocation has enough space to facilitate the new block size
    if (metaData->get_original_size() >= size) {
        metaData->set_requested_size(size);
        return oldp;
    }
    else {
        // If not, we allocate a new space (possibly reused allocation)
        void* allocation_addr = smalloc(size);
        if (!allocation_addr) {
            return NULL;
        }
        // We copy the data and then free the old space
        std::memcpy(allocation_addr, oldp, size);
        sfree(oldp);
        return allocation_addr;
    }

}


size_t _num_free_blocks() {
    size_t num = 0;
    size_t num_of_elem = 0;
    if (allocHistory) {
        for (AllocationData* it = allocHistory; it; it = it->get_next()) {
            num_of_elem++;
            if (it->is_free()) {
                num++;
            }
        }
    }
    return num;
}

size_t _num_free_bytes() {
    size_t num = 0;
    size_t num_of_elem = 0;
    if (allocHistory) {
        for (AllocationData* it = allocHistory; it; it = it->get_next()) {
            num_of_elem++;
            if (it->is_free()) {
                num += it->get_original_size();
            }
        }
    }
    return num;
}

size_t _num_allocated_blocks() {
    size_t num = 0;
    if (allocHistory) {
        for (AllocationData* it = allocHistory; it; it = it->get_next()) {
            num++;
        }
    }
    return num;
}

size_t _num_allocated_bytes() {
    size_t num = 0;
    if (allocHistory) {
        for (AllocationData* it = allocHistory; it; it = it->get_next()) {
            num += it->get_original_size();
        }
    }
    return num;
}

size_t _size_meta_data() {
    return sizeof(AllocationData);
}

size_t _num_meta_data_bytes() {
    size_t num_meta_data_blocks = _num_allocated_blocks();
    return num_meta_data_blocks * _size_meta_data();
}
