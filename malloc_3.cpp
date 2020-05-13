#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

#define MIN_SIZE 0
#define MIN_SPLIT_SIZE 128
#define MAX_SIZE 100000000
#define LARGE_ALLOCATION 131072

class AllocationData {
public:

    void set_is_free(bool free) {
        _is_free = free;
    }

    void set_is_mapp(bool mapp){
        _is_mmap = mapp;
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

    bool is_mapp(){
        return _is_mmap;
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
    bool _is_mmap;
};

/*
 * _original_size is for the metaData+size request
 * _requested_size size is the requested size
 *
 */

/* =========================== Declarations =========================== */

size_t _num_free_blocks();
size_t _num_free_bytes();
size_t _num_allocated_blocks();
size_t _num_allocated_bytes();
size_t _num_meta_data_bytes();
size_t _size_meta_data();

//size_t alignment(size_t size);
void split(AllocationData* metaData, size_t new_requested_size);
void combine(AllocationData* metaData);
void* map_smalloc(size_t size);
void* map_srealloc(void* oldp,size_t size);
/* ================================== Helper Function ================================== */

void split(AllocationData* metaData, size_t new_requested_size) {
    size_t alignedSizeofAllocationData = _size_meta_data();
    int size = metaData->get_original_size()  - new_requested_size -alignedSizeofAllocationData;

    if (size < MIN_SPLIT_SIZE) {
        return;
    }

    AllocationData* newMatadata = (AllocationData*)((size_t)metaData
                                                    + alignedSizeofAllocationData + new_requested_size);
    newMatadata->set_is_free(true);
    newMatadata->set_original_size(size);
    newMatadata->set_allocation_addr((void*)((size_t)newMatadata
                                             + alignedSizeofAllocationData));
    newMatadata->set_next(metaData->get_next());
    newMatadata->set_prev(metaData);

    metaData->set_next(newMatadata);
    metaData->set_original_size(new_requested_size);

    if (newMatadata->get_next()) {
        (newMatadata->get_next())->set_prev(newMatadata);
    }

    combine(newMatadata);
}


void combine(AllocationData* metaData) {
    AllocationData* adjacent_block;
    size_t sizeofAllocationData = sizeof(AllocationData);

    // First, we check if the upper adjacent block is free. In case it is, we combine both
    adjacent_block = metaData->get_next();
    // If the allocated block is the last one on the list, there is no need for combination
    if (adjacent_block && adjacent_block->is_free()) {//TODO:changes were made verify!
        metaData->set_original_size(metaData->get_original_size()
                                    + adjacent_block->get_original_size()
                                    + sizeofAllocationData);
        metaData->set_next(adjacent_block->get_next());
        if (adjacent_block->get_next()) {
            (adjacent_block->get_next())->set_prev(metaData);
        }
    }

    // Now, we check if the lower adjacent block is free. In case it is, we combine both
    adjacent_block = metaData->get_prev();
    if (adjacent_block && adjacent_block->is_free()) {//TODO:changes were made verify!
        adjacent_block->set_original_size(metaData->get_original_size()
                                          + adjacent_block->get_original_size()
                                          + sizeofAllocationData);
        adjacent_block->set_next(metaData->get_next());

        if (metaData->get_next()) {
            (metaData->get_next())->set_prev(adjacent_block);
        }
    }
}


/* ================================== Helper Function End ================================== */
AllocationData* allocHistory = NULL;
AllocationData* mapAllocHistory = NULL;

void* smalloc(size_t size) {
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }
    if(size >=LARGE_ALLOCATION){
        return map_smalloc(size);
    }
    bool wildernessFlag = false;
    AllocationData* metaData = NULL;
    AllocationData* it = NULL;
    // First, we search for freed space in our global list
    if (allocHistory) {
        for (it = allocHistory; it; it = it->get_next()) {
            // Checking if there is a big enough *free* space
            if (it->get_requested_size() >= size && it->is_free()) {
                metaData = it;
                break;
            }
            // Checking for wilderness option
            if (!(it->get_next()) && it->is_free() && it->get_original_size() < size) {
                metaData = it;
                void *allocAddition = sbrk(size - it->get_original_size());//adding the delta betwen what wilderness had and the size we need
                if (allocAddition == (void *) (-1)) {sbrk(it->get_original_size() - size);//removing the delta betwen what wilderness had and the size we need
                    return NULL;
                }
                wildernessFlag = true;
            }
        }
        if (metaData) {
            metaData->set_is_free(false);
            metaData->set_requested_size(size);
            if (wildernessFlag) {
                metaData->set_original_size(size);
            }
            if (metaData->get_original_size() > size || wildernessFlag) {
                split(metaData, size);
            }
            return metaData->get_allocation_addr();
        }
    }
    // Not enough freed space was found, so we allocate new space
    // Allocating Metadata
    void *allocation_addr;
    metaData = (AllocationData *) sbrk(sizeof(AllocationData));
    if (metaData == (void *) (-1)) {
        return NULL;
    }

        // Allocating requested_size bytes
        allocation_addr = sbrk(size);
        if (allocation_addr == (void *) (-1)) {
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
    metaData->set_is_mapp(false);

    // Adding the allocation meta-data to the allocation history list
    // For the first allocation
    if (!allocHistory) {
        allocHistory = metaData;
    }
    else {
        // In case there are others
        it = allocHistory;
        while (it->get_next()) {
            it = it->get_next();
        }
        metaData->set_prev(it);
        it->set_next(metaData);
    }

    return allocation_addr;
}

void* map_smalloc(size_t size) {
    AllocationData* metaData = NULL;
    AllocationData* it = NULL;
    if(mapAllocHistory){
        for (it = mapAllocHistory; it; it = it->get_next()) {
            //checking if we have a free slot in the array
            if(it->is_free()){
                metaData=it;
                break;
            }
        }
    }
    void *allocation_addr;
    if (metaData) {//try to put in the existing element the mmap space
        metaData->set_is_free(false);
        metaData->set_requested_size(size);
        if((allocation_addr=mmap(0,size,PROT_READ|PROT_WRITE,MAP_POPULATE | MAP_ANONYMOUS|MAP_PRIVATE,-1,0))==MAP_FAILED){
            return NULL;
        }
        metaData->set_allocation_addr(allocation_addr);
        return metaData->get_allocation_addr();
    }
    //else setting up the meta data for mapped list
    metaData = (AllocationData *) sbrk(sizeof(AllocationData));
    if (metaData == (void *) (-1)) {
        return NULL;
    }
    if((allocation_addr=mmap(0,size,PROT_READ|PROT_WRITE,MAP_POPULATE | MAP_ANONYMOUS|MAP_PRIVATE,-1,0))==MAP_FAILED){
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
    metaData->set_is_mapp(true);
    // Adding the allocation meta-data to the allocation history list
    // For the first allocation
    if (!mapAllocHistory) {
        mapAllocHistory = metaData;
    }
    else {
        // In case there are others
        it = mapAllocHistory;
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
    for (AllocationData *it = allocHistory; it; it = it->get_next()) {
        if (it->get_allocation_addr() == p) {
            // If 'p' was already released, we ignore the action
            if (it->is_free()) {
                return;
            } else {
                it->set_is_free(true);
                combine(it);
                return;
            }
        }
    }
    // We didnt find it in the global list
    // search for p in our  mapped list
    for (AllocationData *it = mapAllocHistory; it; it = it->get_next()) {
        if (it->get_allocation_addr() == p) {
            // If 'p' was already released, we ignore the action
            if (it->is_free()) {
                return;
            } else {
                it->set_is_free(true);
                munmap(it->get_allocation_addr(), it->get_original_size());
                return;
            }
        }
    }
}

void* srealloc(void* oldp,size_t size){
    if(size<= MIN_SIZE || size > MAX_SIZE){
        return NULL;
    }
    // If oldp is NULL, we allocate space for 'size' bytes and return a pointer to it
    if (!oldp) {
        return smalloc(size);
    }
    if(size >= LARGE_ALLOCATION){//if its a big realloc map_srealloc will handle the request
        return  map_srealloc(oldp,size);
    }
    // If not, we search for it assuming oldp is a pointer to a previously allocated block
    AllocationData* metaData = NULL;
    for (AllocationData* it = allocHistory; it; it = it->get_next()) {
        if (it->get_allocation_addr() == oldp) {
            metaData = it;
            break;
        }
    }
    // We check if the previously made allocation is big enough to facilitate the new block size
    if (metaData->get_original_size() >= size) {
        metaData->set_requested_size(size);
        if (metaData->get_original_size() > size) {
            split(metaData, size);
        }
        return oldp;
    }
    else {
        // We check for wilderness option
        if (!(metaData->get_next())) {
            void* allocAddition = sbrk(size - metaData->get_original_size());
            if (allocAddition == (void*)(-1)) {
                sbrk(metaData->get_original_size() - size);
                return NULL;
            }
            metaData->set_requested_size(size);
            metaData->set_original_size(size);
            return metaData->get_allocation_addr();
        }

        // We check if upper block is free and big enough to facilitate the new allocation
        //in this case we will combain all three blocks
        if (metaData->get_next() && metaData->get_next()->is_free()) {
            size_t combinedSize = metaData->get_original_size()
                                  + _size_meta_data() + metaData->get_next()->get_original_size();
            if (combinedSize >= size) {
                combine(metaData);
                split(metaData, size);
                return metaData->get_allocation_addr();
            }
        }
            // We check if lower block is free and big enough to facilitate the new allocation
            //if we reached here means upper block is not free
            //and we can combain only current block with lower one
        else if (metaData->get_prev() && metaData->get_prev()->is_free()) {
            size_t combinedSize = metaData->get_original_size()
                                  + _size_meta_data() + metaData->get_next()->get_original_size();
            if (combinedSize >= size) {
                combine(metaData);
                split(metaData, size);
                return metaData->get_allocation_addr();
            }
        }

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

//when we eneter here oldp and size are vaild.
void* map_srealloc(void* oldp,size_t size){
    void *map_allocation_addr;
    AllocationData* metaData = NULL;
    for (AllocationData* it = mapAllocHistory; it; it = it->get_next()) {
        if (it->get_allocation_addr() == oldp) {
            metaData = it;
            break;
        }
    }
    //with map data allocation if it was free before the system
    //wont hold a old ptr
    if (metaData->get_original_size() > size  ) {//this will alocate the bigger or smaller requests
        if ((map_allocation_addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE,
                                        -1, 0)) == MAP_FAILED) {
            return NULL;
        }
        std::memcpy(map_allocation_addr, oldp, size);
        munmap(oldp, metaData->get_original_size());
        metaData->set_original_size(size);
        metaData->set_requested_size(size);
        metaData->set_allocation_addr(map_allocation_addr);
        return map_allocation_addr;
    }
    else if (metaData->get_original_size() < size  ) {//this will alocate the bigger or smaller requests
        if ((map_allocation_addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE,
                                        -1, 0)) == MAP_FAILED) {
            return NULL;
        }
        std::memcpy(map_allocation_addr, oldp, metaData->get_requested_size());
        munmap(oldp, metaData->get_original_size());
        metaData->set_original_size(size);
        metaData->set_requested_size(size);
        metaData->set_allocation_addr(map_allocation_addr);
        return map_allocation_addr;
    }
    //do noting
    else if (metaData->get_original_size() == size ){
        return oldp;
    }
    map_allocation_addr = smalloc(size);
    if (!map_allocation_addr) {
        return NULL;
    }
    // We copy the data and then free the old space
    std::memcpy(map_allocation_addr, oldp, size);
    sfree(oldp);
    return map_allocation_addr;
}




size_t _num_free_bytes() {
    size_t num = 0;
    size_t num_of_elem = 0;
    if (allocHistory) {
        for (AllocationData* it = allocHistory; it; it = it->get_next()) {
            num_of_elem++;
            if (it->is_free()) {
                num += it->get_requested_size();
            }
        }
    }
    return num;
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

size_t _num_allocated_blocks() {
    size_t num = 0;
    if (allocHistory) {
        for (AllocationData *it = allocHistory; it; it = it->get_next()) {
            num++;
        }
    }
    if (mapAllocHistory) {
        for (AllocationData *it = mapAllocHistory; it; it = it->get_next()) {
            if (!it->is_free()) {
                num++;

            }
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
    if (mapAllocHistory) {
        for (AllocationData *it = mapAllocHistory; it; it = it->get_next()) {
            if (it->is_free()) {
                num += it->get_original_size();
            }
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


