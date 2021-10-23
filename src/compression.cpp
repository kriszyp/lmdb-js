
// This file contains code from the node-lmdb project
// Copyright (c) 2013-2017 Timur Kristóf
// Copyright (c) 2021 Kristopher Tate
// Licensed to you under the terms of the MIT license
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "lz4.h"
#include "lmdb-store.h"
#include <atomic>

using namespace v8;
using namespace node;

thread_local LZ4_stream_t* Compression::stream = nullptr;
Compression::Compression() {
}
Compression::~Compression() {
    delete dictionary;
}
NAN_METHOD(Compression::ctor) {
    unsigned int compressionThreshold = 1000;
    char* dictionary = nullptr;
    unsigned int dictSize = 0;
    if (info[0]->IsObject()) {
        Local<Value> dictionaryOption = Nan::To<v8::Object>(info[0]).ToLocalChecked()->Get(Nan::GetCurrentContext(), Nan::New<String>("dictionary").ToLocalChecked()).ToLocalChecked();
        if (!dictionaryOption->IsUndefined()) {
            if (!node::Buffer::HasInstance(dictionaryOption)) {
                return Nan::ThrowError("Dictionary must be a buffer");
            }
            dictSize = node::Buffer::Length(dictionaryOption);
            dictSize = (dictSize >> 3) << 3; // make sure it is word-aligned
            unsigned int newTotalSize = dictSize + 4096;
            dictionary = new char[newTotalSize];
            memcpy(dictionary, node::Buffer::Data(dictionaryOption), dictSize);
        }
        Local<Value> thresholdOption = Nan::To<v8::Object>(info[0]).ToLocalChecked()->Get(Nan::GetCurrentContext(), Nan::New<String>("threshold").ToLocalChecked()).ToLocalChecked();
        if (thresholdOption->IsNumber()) {
            compressionThreshold = thresholdOption->IntegerValue(Nan::GetCurrentContext()).FromJust();
        }
    }
    if (!dictionary) {
        dictionary = new char[4096];
    }
    Compression* compression = new Compression();
    compression->dictionary = dictionary;
    compression->decompressTarget = dictionary + dictSize;
    compression->decompressSize = 4096;
    compression->acceleration = 1;
    compression->compressionThreshold = compressionThreshold;
    compression->Wrap(info.This());
    compression->Ref();
    compression->makeUnsafeBuffer();
    info.This()->Set(Nan::GetCurrentContext(), Nan::New<String>("address").ToLocalChecked(), Nan::New<Number>((double) (size_t) compression));

    return info.GetReturnValue().Set(info.This());
}

void Compression::makeUnsafeBuffer() {
    Local<Object> newBuffer = Nan::NewBuffer(
        decompressTarget,
        decompressSize,
        [](char*, void* data) {
            // free the data once it is not used
            //delete data;
        },
        dictionary
    ).ToLocalChecked();
    unsafeBuffer.Reset(Isolate::GetCurrent(), newBuffer);
}

void Compression::decompress(MDB_val& data, bool &isValid, bool canAllocate) {
    uint32_t uncompressedLength;
    int compressionHeaderSize;
    unsigned char* charData = (unsigned char*) data.mv_data;

    if (charData[0] == 254) {
        uncompressedLength = ((uint32_t)charData[1] << 16) | ((uint32_t)charData[2] << 8) | (uint32_t)charData[3];
        compressionHeaderSize = 4;
    }
    else if (charData[0] == 255) {
        uncompressedLength = ((uint32_t)charData[4] << 24) | ((uint32_t)charData[5] << 16) | ((uint32_t)charData[6] << 8) | (uint32_t)charData[7];
        compressionHeaderSize = 8;
    }
    else {
        fprintf(stderr, "Unknown status byte %u\n", charData[0]);
        if (canAllocate)
            Nan::ThrowError("Unknown status byte");
        isValid = false;
        return;
    }
    //TODO: For larger blocks with known encoding, it might make sense to allocate space for it and use an ExternalString
    //fprintf(stdout, "compressed size %u uncompressedLength %u, first byte %u\n", data.mv_size, uncompressedLength, charData[compressionHeaderSize]);
    if (uncompressedLength > decompressSize) {
        if (canAllocate)
            expand(uncompressedLength);
        else {
            isValid = false;
            return;
        }
    }
    int written = LZ4_decompress_safe_usingDict(
        (char*)charData + compressionHeaderSize, decompressTarget,
        data.mv_size - compressionHeaderSize, uncompressedLength,
        dictionary, decompressTarget - dictionary);
    //fprintf(stdout, "first uncompressed byte %X %X %X %X %X %X\n", uncompressedData[0], uncompressedData[1], uncompressedData[2], uncompressedData[3], uncompressedData[4], uncompressedData[5]);
    if (written < 0) {
        //fprintf(stderr, "Failed to decompress data %u %u %u %u\n", charData[0], data.mv_size, compressionHeaderSize, uncompressedLength);
        if (canAllocate)
            Nan::ThrowError("Failed to decompress data");
        isValid = false;
        return;
    }
    data.mv_data = decompressTarget;
    data.mv_size = uncompressedLength;
    isValid = true;

}

void Compression::expand(unsigned int size) {
    unsigned int dictSize = decompressTarget - dictionary;
    decompressSize = size * 2;
    unsigned int newTotalSize = dictSize + decompressSize;
    char* oldSpace = dictionary;
    dictionary = new char[newTotalSize];
    decompressTarget = dictionary + dictSize;
    memcpy(dictionary, oldSpace, dictSize);
    makeUnsafeBuffer();
}

int Compression::compressInstruction(EnvWrap* env, double* compressionAddress) {
    MDB_val value;
    value.mv_data = (void*)((size_t) * (compressionAddress - 1));
    value.mv_size = *(((uint32_t*)compressionAddress) - 3);
    argtokey_callback_t compressedData = compress(&value, nullptr);
    if (compressedData) {
        *(((uint32_t*)compressionAddress) - 3) = value.mv_size;
        *((size_t*)(compressionAddress - 1)) = (size_t)value.mv_data;
        int64_t status = std::atomic_exchange((std::atomic<int64_t>*) compressionAddress, (int64_t) 0);
        if (status == 1 && env) {
fprintf(stderr,"n");
            pthread_mutex_lock(env->writingLock);
            pthread_cond_signal(env->writingCond);
            pthread_mutex_unlock(env->writingLock);
            //fprintf(stderr, "sent compression completion signal\n");
        }
        //fprintf(stdout, "compressed to %p %u %u %p\n", value.mv_data, value.mv_size, status, env);
        return 0;
    } else {
        fprintf(stdout, "failed to compress\n");
        return 1;
    }
}

argtokey_callback_t Compression::compress(MDB_val* value, void (*freeValue)(MDB_val&)) {
    size_t dataLength = value->mv_size;
    char* data = (char*)value->mv_data;
    if (value->mv_size < compressionThreshold && !(value->mv_size > 0 && ((uint8_t*)data)[0] >= 250))
        return freeValue; // don't compress if less than threshold (but we must compress if the first byte is the compression indicator)
    bool longSize = dataLength >= 0x1000000;
    int prefixSize = (longSize ? 8 : 4);
    int maxCompressedSize = LZ4_COMPRESSBOUND(dataLength);
    char* compressed = new char[maxCompressedSize + prefixSize];
    //fprintf(stdout, "compressing %u\n", dataLength);
    if (!stream)
        stream = LZ4_createStream();
    LZ4_loadDict(stream, dictionary, decompressTarget - dictionary);
    int compressedSize = LZ4_compress_fast_continue(stream, data, compressed + prefixSize, dataLength, maxCompressedSize, acceleration);
    if (compressedSize > 0) {
        if (freeValue)
            freeValue(*value);
        uint8_t* compressedData = (uint8_t*)compressed;
        if (longSize) {
            compressedData[0] = 255;
            compressedData[2] = (uint8_t)(dataLength >> 40u);
            compressedData[3] = (uint8_t)(dataLength >> 32u);
            compressedData[4] = (uint8_t)(dataLength >> 24u);
            compressedData[5] = (uint8_t)(dataLength >> 16u);
            compressedData[6] = (uint8_t)(dataLength >> 8u);
            compressedData[7] = (uint8_t)dataLength;
        }
        else {
            compressedData[0] = 254;
            compressedData[1] = (uint8_t)(dataLength >> 16u);
            compressedData[2] = (uint8_t)(dataLength >> 8u);
            compressedData[3] = (uint8_t)dataLength;
        }
        value->mv_size = compressedSize + prefixSize;
        value->mv_data = compressed;
        return ([](MDB_val &value) -> void {
            delete[] (char*)value.mv_data;
        });
    }
    else {
        delete[] compressed;
        return nullptr;
    }
}

class CompressionWorker : public Nan::AsyncWorker {
  public:
    CompressionWorker(EnvWrap* env, double* compressionAddress, Nan::Callback *callback)
      : Nan::AsyncWorker(callback), env(env), compressionAddress(compressionAddress) {}


    void Execute() {
        uint64_t compressionPointer;
        compressionPointer = std::atomic_exchange((std::atomic<int64_t>*) compressionAddress, (int64_t) 2);
        if (compressionPointer > 1) {
            Compression* compression = (Compression*)(size_t) * ((double*)&compressionPointer);
            compression->compressInstruction(env, compressionAddress);
        }
    }
    void HandleOKCallback() {
        // don't actually call the callback, no need
    }

  private:
    EnvWrap* env;
    double* compressionAddress;
};

NAN_METHOD(EnvWrap::compress) {
    EnvWrap *env = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    size_t compressionAddress = Local<Number>::Cast(info[0])->Value();
    Nan::Callback* callback = new Nan::Callback(Local<v8::Function>::Cast(info[1]));
    CompressionWorker* worker = new CompressionWorker(env, (double*) compressionAddress, callback);
    Nan::AsyncQueueWorker(worker);
}
