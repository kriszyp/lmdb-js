#include "lmdb-store.h"


KeySpaceHolder::KeySpaceHolder() {
    previousSpace = nullptr;
}
KeySpaceHolder::KeySpaceHolder(KeySpaceHolder* existingSpace, uint8_t* existingData) {
    previousSpace = existingSpace;
    data = existingData;
}
KeySpaceHolder::~KeySpaceHolder() {
    if (previousSpace)
        delete previousSpace;
    delete[] data;
}

uint8_t* KeySpace::getTarget() {
    if (position + MDB_MAXKEYSIZE > size) {
        if (fixedSize) {
            Nan::ThrowError("Key is too large");
            return nullptr;
        } else {
            previousSpace = new KeySpaceHolder(previousSpace, data);
            size = size << 1; // grow on each expansion
            data = new uint8_t[size];
        }
    }
    return &data[position];
}
KeySpace::KeySpace(bool fixed) {
    fixedSize = fixed;
    position = 0;
    size = fixed ? MDB_MAXKEYSIZE + 8 : 8192;
    data = new uint8_t[size];
}
#ifdef _WIN32
#define ntohl _byteswap_ulong
#define htonl _byteswap_ulong
#endif

void load32LE(MDB_val &val, uint32_t* target) {
    // copy and swap at the same time, and guarantee null termination
    uint32_t* source = (uint32_t*) val.mv_data;
    unsigned int size = val.mv_size - 4;
    *target++ = ntohl(*source++);
    memcpy(target, source, size);
    /*
    uint32_t* end = source + (size >> 2);
    for (; source < end; source++) {
        *target = ntohl(*source);
        target++;
    }
    *target = ntohl(*source << (32 - ((size & 3) << 3)));*/
}


void make32LE(MDB_val &val) {
/*
    uint8_t* bytes = (uint8_t*) val.mv_data;
    unsigned int size = val.mv_size;
    if (val.mv_size & 1) {
        if (bytes[size - 1] == 0)
            val.mv_size = --size;
        else
            return;
    }
    size = size >> 1;
    if (((uint16_t*)bytes)[size - 1] == 0) {
        if (((uint16_t*)bytes)[size - 2] == 0)
            val.mv_size -= 4;
        else
            val.mv_size -= 2;
    }
*/ 
    uint32_t* buffer = (uint32_t*) val.mv_data;
    *buffer = htonl(*buffer);/*
    unsigned int size = val.mv_size;
    uint32_t* end = buffer + (size >> 2);
    for (; buffer < end; buffer++) {
        *buffer = htonl(*buffer);
    }
    *buffer = htonl(*buffer << (32 - ((size & 3) << 3)));*/
}
// compare items by 32-bit comparison, a is user provided and assumed to be zero terminated/padded
// which allows us to do the full 32-bit comparisons safely
int compareFast(const MDB_val *a, const MDB_val *b) {
    uint32_t* dataA = (uint32_t*) a->mv_data;
    uint32_t* dataB = (uint32_t*) b->mv_data;
    size_t remaining = b->mv_size;
    uint32_t aVal, bVal;
    while(remaining >= 4) {
        aVal = ntohl(*dataA);
        bVal = ntohl(*dataB);
        if (aVal > bVal)
            return 1;
        if (aVal < bVal)
            return -1;
        /*diff = (int64_t) ntohl(*dataA) - (int64_t) ntohl(*dataB);
        if (diff)
            return diff;*/
        dataA++;
        dataB++;
        remaining -= 4;
    }
    if (remaining) {
        aVal = ntohl(*dataA);
        bVal = ntohl(*dataB & (remaining == 2 ? 0x0000ffff : remaining == 1 ? 0x000000ff : 0x00ffffff));
        if (aVal > bVal)
            return 1;
        if (aVal < bVal)
            return -1;
    }
    return a->mv_size - b->mv_size;
}