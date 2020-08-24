#include "node-lmdb.h"
#include <string.h>
#include <stdio.h>

/*
control character types:
1 - metadata
6 - false
7 - true
8- 16 - negative doubles
16-24 positive doubles
27 - used for escaping control bytes in strings
30 - multipart separator
> 31 normal string characters
*/
/*
* Convert arbitrary scalar values to buffer bytes with type preservation and type-appropriate ordering
*/
argtokey_callback_t valueToKey(const Local<Value> &jsKey, MDB_val &mdbKey, bool &isValid, bool fullLength) {
    if (jsKey->IsString()) {
        writeValueToEntry(jsKey, &mdbKey);
        int needsEscaping = 0;
        uint8_t* position = (uint8_t*) mdbKey.mv_data;
        for (uint8_t* end = position + mdbKey.mv_size; position < end; position++) {
            if (*position < 32)
                needsEscaping++;
        }
        if (needsEscaping) {
            int newSize = mdbKey.mv_size + needsEscaping;
            uint8_t* escaped = new uint8_t[newSize];
            uint8_t* position = (uint8_t*) mdbKey.mv_data;
            int escapePosition = 0;
            for (uint8_t* end = position + mdbKey.mv_size; position < end; position++) {
                uint8_t c = escaped[escapePosition++] = *position;
                if (c < 32) {
                    escaped[escapePosition - 1] = 27;
                    escaped[escapePosition++] = c;
                }
            }
            delete (char*) mdbKey.mv_data;
            mdbKey.mv_data = escaped;
            mdbKey.mv_size = newSize;
        }
        return ([](MDB_val &key) -> void {
            delete[] (char*)key.mv_data;
        });
    }
    uint8_t* keyBytes;
    int size;
    if (jsKey->IsNumber()) {
        double number = Local<Number>::Cast(jsKey)->Value();
        uint64_t asInt = *((uint64_t*) &number);
        keyBytes = new uint8_t[9]; // TODO: if last is zero, this can be 8
        if (number < 0) {
            asInt = asInt ^ 0x7fffffffffffffff;
            keyBytes[0] = (uint8_t) (asInt >> 60);
        } else {
            keyBytes[0] = (uint8_t) (asInt >> 60) | 0x10;
        }
        // TODO: Use byte_swap to do this faster
        keyBytes[1] = (uint8_t) (asInt >> 52) & 0xff;
        keyBytes[2] = (uint8_t) (asInt >> 44) & 0xff;
        keyBytes[3] = (uint8_t) (asInt >> 36) & 0xff;
        keyBytes[4] = (uint8_t) (asInt >> 28) & 0xff;
        keyBytes[5] = (uint8_t) (asInt >> 20) & 0xff;
        keyBytes[6] = (uint8_t) (asInt >> 12) & 0xff;
        keyBytes[7] = (uint8_t) (asInt >> 4) & 0xff;
        keyBytes[8] = (uint8_t) (asInt << 4) & 0xff;
        if (keyBytes[8] == 0 && !fullLength) {
            if (keyBytes[6] == 0 && keyBytes[7] == 0) {
                if (keyBytes[5] == 0 && keyBytes[4] == 0)
                        size = 4;
                else
                    size = 6;
            } else
                size = 8;
        } else
            size = 9;
       //fprintf(stdout, "asInt %x %x %x %x %x %x %x %x %x\n", keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3], keyBytes[4], keyBytes[5], keyBytes[6], keyBytes[7], keyBytes[8]);
    } else if (jsKey->IsArray()) {
        Local<Array> array = Local<Array>::Cast(jsKey);
        int length = array->Length();
        MDB_val* segments = new MDB_val[length];
        argtokey_callback_t* callbacks = new argtokey_callback_t[length];
        size = length > 0 ? length - 1 : 0;
        Local<Context> context = Nan::GetCurrentContext();
        for (int i = 0; i < length; i++) {
            auto freeData = valueToKey(array->Get(context, i).ToLocalChecked(), segments[i], isValid, true);
            callbacks[i] = freeData;
            size += segments[i].mv_size;
        }
        keyBytes = new uint8_t[size];
        int position = 0;
        for (int i = 0; i < length; i++) {
            if (i > 0)
                keyBytes[position++] = 30;
            memcpy(&keyBytes[position], segments[i].mv_data, segments[i].mv_size);
            position += segments[i].mv_size;
            if (callbacks[i]) {
                callbacks[i](segments[i]);
            }
        }
        delete[] segments;
        delete[] callbacks;
    } else if (jsKey->IsNullOrUndefined()) {
        keyBytes = new uint8_t[1];
        size = 1;
        keyBytes[0] = 0;
    } else if (jsKey->IsBoolean()) {
        keyBytes = new uint8_t[1];
        size = 1;
        keyBytes[0] = jsKey->IsTrue() ? 7 : 6;
    } else if (node::Buffer::HasInstance(jsKey)) {
        mdbKey.mv_size = node::Buffer::Length(jsKey);
        mdbKey.mv_data = node::Buffer::Data(jsKey);
        return nullptr;
    } else {
        fprintf(stderr, "Unknown type");
        Nan::ThrowError("Invalid type for key.");
        isValid = false;
        return nullptr;
    }
    mdbKey.mv_data = keyBytes;
    mdbKey.mv_size = size;
    return ([](MDB_val &key) -> void {
        delete[] (char*)key.mv_data;
    });
}

Local<Value> keyToValue(MDB_val &val) {
    Local<Value> value;
    int consumed = 0;
    uint8_t* keyBytes = (uint8_t*) val.mv_data;
    int size = val.mv_size;
    uint8_t controlByte = keyBytes[0];
    if (controlByte < 24) {
        if (controlByte < 8) {
            consumed = 1;
            if (controlByte == 6) {
                value = Nan::New<Boolean>(false);
            } else if (controlByte == 7) {
                value = Nan::New<Boolean>(true);
            } else if (controlByte == 0) {
                value = Nan::Null();
            } else {
                if (controlByte < 27) {
                    return Nan::CopyBuffer(
                        (char*)val.mv_data,
                        val.mv_size
                    ).ToLocalChecked();
                }
            }
        } else {
            uint64_t asInt = ((uint64_t) keyBytes[0] << 60) | ((uint64_t) keyBytes[1] << 52) | ((uint64_t) keyBytes[2] << 44) | ((uint64_t) keyBytes[3] << 36);
            if (size > 4) {
                asInt |= ((uint64_t) keyBytes[4] << 28) | ((uint64_t) keyBytes[5] << 20);
                if (size > 6) {
                    asInt |= ((uint64_t) keyBytes[6] << 12) | ((uint64_t) keyBytes[7] << 4);
                    if (size > 8) {
                        asInt |= (uint64_t) keyBytes[8] >> 4;
                    }
                }
            }
            if (controlByte < 16)
                asInt = asInt ^ 0x7fffffffffffffff;
//           fprintf(stdout, "asInt %x %x \n",asInt, asInt >> 32);

            value = Nan::New<Number>(*((double*) &asInt));
            consumed = 9;
        }
    } else {
        bool needsEscaping = false;
        consumed = val.mv_size;
        bool isOneByte = true;
        int8_t* position = ((int8_t*) val.mv_data);
        int8_t* end = position + consumed;
        for (; position < end; position++) {
            if (*position < 32) { // by using signed chars, non-latin is negative and escapes and separators are less than 32
                int8_t c = *position;
                if (c < 0) {
                    isOneByte = false;
                } else if (c == 30) {
                    consumed = position - ((int8_t*) val.mv_data);
                    break;
                } else if (c == 27) {
                    // needs escaping
                    needsEscaping = true;
                    isOneByte = false;
                    position++;
                }
            }
        }
        if (isOneByte) {
            value = v8::String::NewFromOneByte(Isolate::GetCurrent(), (uint8_t*) val.mv_data, v8::NewStringType::kNormal, consumed).ToLocalChecked();
        } else {
            if (needsEscaping) {
                char* escaped = new char[consumed];
                int convertedChars = 0;
                position = ((int8_t*) val.mv_data);
                end = position + consumed;
                for (; position < end; position++) {
                    char c = escaped[convertedChars++] = *position;
                    if (c == 27) {
                        position++;
                        escaped[convertedChars - 1] = *position;
                    }
                }

                value = Nan::New<v8::String>(escaped, convertedChars).ToLocalChecked();
                delete[] escaped;
            } else
                value = Nan::New<v8::String>((char*) val.mv_data, consumed).ToLocalChecked();
        }
    }
    if (consumed < size) {
        if (keyBytes[consumed] != 30) {
            Nan::ThrowError("Invalid separator byte");
            return Nan::Undefined();
        }
        MDB_val nextPart;
        nextPart.mv_size = size - consumed - 1;
        nextPart.mv_data = &keyBytes[consumed + 1];
        Local<Value> nextValue = keyToValue(nextPart);
        v8::Local<v8::Array> resultsArray;
        Local<Context> context = Nan::GetCurrentContext();
        if (nextValue->IsArray()) {
            // unshift
            resultsArray = Local<Array>::Cast(nextValue);
            int length = resultsArray->Length();
            for (int i = 0; i < length; i++) {
                resultsArray->Set(context, i + 1, resultsArray->Get(context, i).ToLocalChecked());
            }
        } else {
            resultsArray = Nan::New<v8::Array>(2);
            resultsArray->Set(context, 1, nextValue);
        }
        resultsArray->Set(context, 0, value);
        value = resultsArray;
    }
    return value;
}

NAN_METHOD(bufferToKeyValue) {
    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowError("Invalid key. Should be a Buffer.");
        return;
    }
    
    MDB_val key;
    key.mv_size = node::Buffer::Length(info[0]);
    key.mv_data = node::Buffer::Data(info[0]);
    info.GetReturnValue().Set(keyToValue(key));
}
NAN_METHOD(keyValueToBuffer) {
    MDB_val key;
    bool isValid = true;
    auto freeKey = valueToKey(info[0], key, isValid, false);
    if (!isValid)
        return;
    Nan::MaybeLocal<v8::Object> buffer;
    if (freeKey) {
        buffer = Nan::NewBuffer(
            (char*)key.mv_data,
            key.mv_size);
    } else {
        buffer = Nan::NewBuffer(
            (char*)key.mv_data,
            key.mv_size,
            [](char *, void *) {
                // do nothing
            },
            nullptr
        );
    }
    info.GetReturnValue().Set(buffer.ToLocalChecked());
}
