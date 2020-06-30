
// This file is part of node-lmdb, the Node.js binding for lmdb
// Copyright (c) 2013-2017 Timur Kristóf
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

#include "node-lmdb.h"
#include "lz4.h"
#include <string.h>
#include <stdio.h>

void setupExportMisc(Local<Object> exports) {
    Local<Object> versionObj = Nan::New<Object>();

    int major, minor, patch;
    char *str = mdb_version(&major, &minor, &patch);
    Local<Context> context = Nan::GetCurrentContext();
    versionObj->Set(context, Nan::New<String>("versionString").ToLocalChecked(), Nan::New<String>(str).ToLocalChecked());
    versionObj->Set(context, Nan::New<String>("major").ToLocalChecked(), Nan::New<Integer>(major));
    versionObj->Set(context, Nan::New<String>("minor").ToLocalChecked(), Nan::New<Integer>(minor));
    versionObj->Set(context, Nan::New<String>("patch").ToLocalChecked(), Nan::New<Integer>(patch));

    exports->Set(context, Nan::New<String>("version").ToLocalChecked(), versionObj);
    Nan::SetMethod(exports, "getLastVersion", getLastVersion);
    Nan::SetMethod(exports, "bufferToKeyValue", bufferToKeyValue);
    Nan::SetMethod(exports, "keyValueToBuffer", keyValueToBuffer);
}

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Local<Object> options) {
    Local<Context> context = Nan::GetCurrentContext();
    Local<Value> opt = options->Get(context, Nan::New<String>(name).ToLocalChecked()).ToLocalChecked();
    #if NODE_VERSION_AT_LEAST(12,0,0)
    if (opt->IsBoolean() ? opt->BooleanValue(Isolate::GetCurrent()) : defaultValue) {
    #else
    if (opt->IsBoolean() ? opt->BooleanValue(context).ToChecked() : defaultValue) {
    #endif;
        *flags |= flag;
    }
}

NodeLmdbKeyType keyTypeFromOptions(const Local<Value> &val, NodeLmdbKeyType defaultKeyType) {
    if (!val->IsObject()) {
        return defaultKeyType;
    }
    auto obj = Local<Object>::Cast(val);

    NodeLmdbKeyType keyType = defaultKeyType;
    int keyIsUint32 = 0;
    int keyIsBuffer = 0;
    int keyIsString = 0;
    
    setFlagFromValue(&keyIsUint32, 1, "keyIsUint32", false, obj);
    setFlagFromValue(&keyIsString, 1, "keyIsString", false, obj);
    setFlagFromValue(&keyIsBuffer, 1, "keyIsBuffer", false, obj);
    
    const char *keySpecificationErrorText = "You can't specify multiple key types at once. Either set keyIsUint32, or keyIsBuffer or keyIsString (default).";
    
    if (keyIsUint32) {
        keyType = NodeLmdbKeyType::Uint32Key;
        if (keyIsBuffer || keyIsString) {
            Nan::ThrowError(keySpecificationErrorText);
            return NodeLmdbKeyType::InvalidKey;
        }
    }
    else if (keyIsBuffer) {
        keyType = NodeLmdbKeyType::BinaryKey;
        
        if (keyIsUint32 || keyIsString) {
            Nan::ThrowError(keySpecificationErrorText);
            return NodeLmdbKeyType::InvalidKey;
        }
    }
    else if (keyIsString) {
        keyType = NodeLmdbKeyType::StringKey;
    }
    
    return keyType;
}

NodeLmdbKeyType inferKeyType(const Local<Value> &val) {
    if (val->IsString()) {
        return NodeLmdbKeyType::StringKey;
    }
    if (val->IsUint32()) {
        return NodeLmdbKeyType::Uint32Key;
    }
    if (node::Buffer::HasInstance(val)) {
        return NodeLmdbKeyType::BinaryKey;
    }
    
    return NodeLmdbKeyType::InvalidKey;
}

NodeLmdbKeyType inferAndValidateKeyType(const Local<Value> &key, const Local<Value> &options, NodeLmdbKeyType dbiKeyType, bool &isValid) {
    auto keyType = keyTypeFromOptions(options, NodeLmdbKeyType::DefaultKey);
    auto inferredKeyType = inferKeyType(key);
    isValid = false;
    
    if (keyType != NodeLmdbKeyType::DefaultKey && inferredKeyType != keyType) {
        Nan::ThrowError("Specified key type doesn't match the key you gave.");
        return NodeLmdbKeyType::InvalidKey;
    }
    else {
        keyType = inferredKeyType;
    }
    if (dbiKeyType == NodeLmdbKeyType::Uint32Key && keyType != NodeLmdbKeyType::Uint32Key) {
        Nan::ThrowError("You specified keyIsUint32 on the Dbi, so you can't use other key types with it.");
        return NodeLmdbKeyType::InvalidKey;
    }
    
    isValid = true;
    return keyType;
}

argtokey_callback_t argToKey(Local<Value> &val, MDB_val &key, NodeLmdbKeyType keyType, bool &isValid) {
    isValid = false;

    if (keyType == NodeLmdbKeyType::DefaultKey) {
        isValid = true;
        return valueToKey(val, key);
    } else if (keyType == NodeLmdbKeyType::StringKey) {
        if (!val->IsString()) {
            Nan::ThrowError("Invalid key. Should be a string. (Specified with env.openDbi)");
            return nullptr;
        }
        
        isValid = true;
        CustomExternalStringResource::writeTo(Local<String>::Cast(val), &key);
        return ([](MDB_val &key) -> void {
            delete[] (uint16_t*)key.mv_data;
        });
    }
    else if (keyType == NodeLmdbKeyType::Uint32Key) {
        if (!val->IsUint32()) {
            Nan::ThrowError("Invalid key. Should be an unsigned 32-bit integer. (Specified with env.openDbi)");
            return nullptr;
        }
        
        isValid = true;
        uint32_t* uint32Key = new uint32_t;
        *uint32Key = val->Uint32Value(Nan::GetCurrentContext()).ToChecked();
        key.mv_size = sizeof(uint32_t);
        key.mv_data = uint32Key;

        return ([](MDB_val &key) -> void {
            delete (uint32_t*)key.mv_data;
        });
    }
    else if (keyType == NodeLmdbKeyType::BinaryKey) {
        if (!node::Buffer::HasInstance(val)) {
            Nan::ThrowError("Invalid key. Should be a Buffer. (Specified with env.openDbi)");
            return nullptr;
        }
        
        isValid = true;
        key.mv_size = node::Buffer::Length(val);
        key.mv_data = node::Buffer::Data(val);
        
        return nullptr;
    }
    else if (keyType == NodeLmdbKeyType::InvalidKey) {
        Nan::ThrowError("Invalid key type. This might be a bug in node-lmdb.");
    }
    else {
        Nan::ThrowError("Unknown key type. This is a bug in node-lmdb.");
    }

    return nullptr;
}

Local<Value> keyToHandle(MDB_val &key, NodeLmdbKeyType keyType) {
    switch (keyType) {
    case NodeLmdbKeyType::DefaultKey:
        return keyToValue(key);
    case NodeLmdbKeyType::Uint32Key:
        return Nan::New<Integer>(*((uint32_t*)key.mv_data));
    case NodeLmdbKeyType::BinaryKey:
        return valToBinary(key);
    case NodeLmdbKeyType::StringKey:
        return valToString(key);
    default:
        Nan::ThrowError("Unknown key type. This is a bug in node-lmdb.");
        return Nan::Undefined();
    }
}

Local<Value> valToStringUnsafe(MDB_val &data) {
    auto resource = new CustomExternalOneByteStringResource(&data);
    auto str = Nan::New<v8::String>(resource);

    return str.ToLocalChecked();
}

Local<Value> valToUtf8(MDB_val &data) {
    const char *buffer = (const char*)(data.mv_data);
    //Isolate *isolate = Isolate::GetCurrent();
    //auto str = v8::String::NewFromOneByte(isolate, buffer, v8::NewStringType::kNormal, data.mv_size);
    auto str = Nan::New<v8::String>(buffer, data.mv_size);

    return str.ToLocalChecked();
}

Local<Value> valToString(MDB_val &data) {
    // UTF-16 buffer
    const uint16_t *buffer = reinterpret_cast<const uint16_t*>(data.mv_data);
    // Number of UTF-16 code points
    size_t n = data.mv_size / sizeof(uint16_t);
    
    // Check zero termination
    if (n < 1 || buffer[n - 1] != 0) {
        Nan::ThrowError("Invalid zero-terminated UTF-16 string");
        return Nan::Undefined();
    }
    
    size_t length = n - 1;
    auto str = Nan::New<v8::String>(buffer, length);

    return str.ToLocalChecked();
}

Local<Value> valToBinary(MDB_val &data) {
    return Nan::CopyBuffer(
        (char*)data.mv_data,
        data.mv_size
    ).ToLocalChecked();
}

Local<Value> valToBinaryUnsafe(MDB_val &data) {
    return Nan::NewBuffer(
        (char*)data.mv_data,
        data.mv_size,
        [](char *, void *) {
            // Data belongs to LMDB, we shouldn't free it here
        },
        nullptr
    ).ToLocalChecked();
}

Local<Value> valToNumber(MDB_val &data) {
    return Nan::New<Number>(*((double*)data.mv_data));
}

Local<Value> valToBoolean(MDB_val &data) {
    return Nan::New<Boolean>(*((bool*)data.mv_data));
}

Local<Value> getVersionAndUncompress(MDB_val &data, bool getVersion, int compressionThreshold, Local<Value> (*successFunc)(MDB_val&)) {
    //fprintf(stdout, "uncompressing %u\n", compressionThreshold);
    int headerSize = 0;
    if (data.mv_size == 0) 
        return successFunc(data);
    unsigned char* charData = (unsigned char*) data.mv_data;
    if (getVersion) {
        lastVersion = *((double*) charData);
        //fprintf(stdout, "getVersion %u\n", lastVersion);
        charData = charData + 8;
        data.mv_data = charData;
        data.mv_size -= 8;
        headerSize = 8;
    }
    unsigned char statusByte = compressionThreshold < 0xffffffff ? charData[0] : 0;
        //fprintf(stdout, "uncompressing status %X\n", statusByte);
    if (statusByte >= 254) {
        uint32_t uncompressedLength;
        int compressionHeaderSize;
        if (statusByte == 254) {
            uncompressedLength = ((uint32_t) charData[1] << 16) | ((uint32_t) charData[2] << 8) | (uint32_t) charData[3];
            compressionHeaderSize = 4;
        } else if (statusByte == 255) {
            uncompressedLength = ((uint32_t) charData[4] << 24) | ((uint32_t) charData[5] << 16) | ((uint32_t) charData[6] << 8) | (uint32_t) charData[7];
            compressionHeaderSize = 8;
        } else {
            Nan::ThrowError("Unknown status byte");
            return Nan::Undefined();
        }
        //fprintf(stdout, "uncompressedLength %u, first byte %u\n", uncompressedLength, charData[compressionHeaderSize]);
        char* uncompressedData = new char[uncompressedLength];
        LZ4_decompress_safe((char*) charData + compressionHeaderSize, uncompressedData, data.mv_size - compressionHeaderSize, uncompressedLength);
        //fprintf(stdout, "first uncompressed byte %X %X %X %X %X %X\n", uncompressedData[0], uncompressedData[1], uncompressedData[2], uncompressedData[3], uncompressedData[4], uncompressedData[5]);
        data.mv_data = uncompressedData;
        data.mv_size = uncompressedLength;
        // TODO: Allow 253 and 252 to denote that it is a latin-only string so can use the CustomExternalOneByteStringResource for large one-byte strings to reduce memory copying
        Local<Value> value = successFunc(data);
        delete[] uncompressedData;
        return value;
    }
    return successFunc(data);
}

NAN_METHOD(getLastVersion) {
    return info.GetReturnValue().Set(Nan::New<Number>(lastVersion));
}

void throwLmdbError(int rc) {
    auto err = Nan::Error(mdb_strerror(rc));
    err.As<Object>()->Set(Nan::GetCurrentContext(), Nan::New("code").ToLocalChecked(), Nan::New(rc));
    return Nan::ThrowError(err);
}

void consoleLog(const char *msg) {
    Local<String> str = Nan::New("console.log('").ToLocalChecked();
    //str = String::Concat(str, Nan::New<String>(msg).ToLocalChecked());
    //str = String::Concat(str, Nan::New("');").ToLocalChecked());

    Local<Script> script = Nan::CompileScript(str).ToLocalChecked();
    Nan::RunScript(script);
}

void consoleLog(Local<Value> val) {
    Local<String> str = Nan::New<String>("console.log('").ToLocalChecked();
    //str = String::Concat(str, Local<String>::Cast(val));
    //str = String::Concat(str, Nan::New<String>("');").ToLocalChecked());

    Local<Script> script = Nan::CompileScript(str).ToLocalChecked();
    Nan::RunScript(script);
}

void consoleLogN(int n) {
    char c[20];
    memset(c, 0, 20 * sizeof(char));
    sprintf(c, "%d", n);
    consoleLog(c);
}

void tryCompress(MDB_val* value, int headerSize) {
    int dataLength = value->mv_size - headerSize;
    char* data = (char*) value->mv_data;
    bool longSize = dataLength >= 0x1000000;
    int prefixSize = (longSize ? 8 : 4) + headerSize;
    int maxCompressedSize = dataLength - 100;
    char* compressed = new char[maxCompressedSize + prefixSize];
    int compressedSize = LZ4_compress_default(data + headerSize, compressed + prefixSize, dataLength, maxCompressedSize);
    if (compressedSize > 0) {
        if (headerSize > 0)
            memcpy(compressed, data, headerSize);
        delete[] value->mv_data;
        uint8_t* compressedData = (uint8_t*) compressed + headerSize;
        if (longSize) {
            compressedData[0] = 255;
            compressedData[2] = (uint8_t) (dataLength >> 40u);
            compressedData[3] = (uint8_t) (dataLength >> 32u);
            compressedData[4] = (uint8_t) (dataLength >> 24u);
            compressedData[5] = (uint8_t) (dataLength >> 16u);
            compressedData[6] = (uint8_t) (dataLength >> 8u);
            compressedData[7] = (uint8_t) dataLength;
        } else {
            compressedData[0] = 254;
            compressedData[1] = (uint8_t) (dataLength >> 16u);
            compressedData[2] = (uint8_t) (dataLength >> 8u);
            compressedData[3] = (uint8_t) dataLength;
        }
        value->mv_data = compressed;
        value->mv_size = compressedSize + prefixSize;
    } else {
        delete[] compressed;
    }
}

void writeUtf8ToEntry(Local<String> str, MDB_val *val, int headerSize) {
    int strLength = str->Length();
    // an optimized guess at buffer length that works >99% of time and has good byte alignment
    int byteLength = str->IsOneByte() ? strLength :
        (((strLength >> 3) + ((strLength + 116) >> 6)) << 3);
    char *data = new char[byteLength + headerSize];
    int utfWritten = 0;
    #if NODE_VERSION_AT_LEAST(10,0,0)
    int bytes = str->WriteUtf8(Isolate::GetCurrent(), data + headerSize, byteLength, &utfWritten, v8::String::WriteOptions::NO_NULL_TERMINATION);
    if (utfWritten < strLength) {
        // we didn't allocate enough memory, need to expand
        delete[] data;
        byteLength = strLength * 3;
        data = new char[byteLength + headerSize];
        bytes = str->WriteUtf8(Isolate::GetCurrent(), data + headerSize, byteLength, &utfWritten, v8::String::WriteOptions::NO_NULL_TERMINATION);
    }
    #else
    str->Write(data, 0);
    #endif;
    val->mv_data = data;
    val->mv_size = bytes + headerSize;
    //fprintf(stdout, "size of data with string %u header size %u\n", val->mv_size, headerSize);
}

void CustomExternalStringResource::writeTo(Local<String> str, MDB_val *val) {
    unsigned int l = str->Length() + 1;
    uint16_t *d = new uint16_t[l];
    #if NODE_VERSION_AT_LEAST(10,0,0)
    str->Write(Isolate::GetCurrent(), d);
    #else
    str->Write(d);
    #endif;
    d[l - 1] = 0;

    val->mv_data = d;
    val->mv_size = l * sizeof(uint16_t);
}

CustomExternalStringResource::CustomExternalStringResource(MDB_val *val) {
    // The UTF-16 data
    this->d = (uint16_t*)(val->mv_data);
    // Number of UTF-16 characters in the string
    size_t n = val->mv_size / sizeof(uint16_t);
    // Silently generate a 0 length if length invalid
    this->l = n ? (n - 1) : 0;
}

CustomExternalStringResource::~CustomExternalStringResource() { }

void CustomExternalStringResource::Dispose() {
    // No need to do anything, the data is owned by LMDB, not us
    
    // But actually need to delete the string resource itself:
    // the docs say that "The default implementation will use the delete operator."
    // while initially I thought this means using delete on the string,
    // apparently they meant just calling the destructor of this class.
    delete this;
}

const uint16_t *CustomExternalStringResource::data() const {
    return this->d;
}

size_t CustomExternalStringResource::length() const {
    return this->l;
}

CustomExternalOneByteStringResource::CustomExternalOneByteStringResource(MDB_val *val) {
    // The Latin data
    this->d = (char*)(val->mv_data);
    // Number of Latin characters in the string
    this->l = val->mv_size;
}

CustomExternalOneByteStringResource::~CustomExternalOneByteStringResource() { }

void CustomExternalOneByteStringResource::Dispose() {
    // No need to do anything, the data is owned by LMDB, not us
    
    // But actually need to delete the string resource itself:
    // the docs say that "The default implementation will use the delete operator."
    // while initially I thought this means using delete on the string,
    // apparently they meant just calling the destructor of this class.
    delete this;
}

const char *CustomExternalOneByteStringResource::data() const {
    return this->d;
}

size_t CustomExternalOneByteStringResource::length() const {
    return this->l;
}
