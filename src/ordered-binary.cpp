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
0 - multipart separator
> 31 normal string characters
*/
/*
* Convert arbitrary scalar values to buffer bytes with type preservation and type-appropriate ordering
*/

MDB_val arrayElement;
bool valueToKey(const Local<Value> &jsKey, MDB_val &mdbKey, KeySpace &keySpace, bool inArray) {
    if (!inArray && keySpace.fixedSize) {
        keySpace.position = 0;
    }
    uint8_t* targetBytes;
    if (!(targetBytes = keySpace.getTarget(10)))
        return false;
    int end = keySpace.size;
    int bytesWritten;
    if (jsKey->IsString()) {
        int utfWritten = 0;
        Local<String> string = Local<String>::Cast(jsKey);
        bytesWritten = string->WriteUtf8(Isolate::GetCurrent(), (char*) targetBytes, end - keySpace.position - 1, &utfWritten, v8::String::WriteOptions::NO_NULL_TERMINATION);
        if (utfWritten < string->Length()) {
            if (!(targetBytes = keySpace.getTarget(string->Length() * 3 + 1)))
                return false;
            bytesWritten = string->WriteUtf8(Isolate::GetCurrent(), (char*) targetBytes, end - keySpace.position - 1, &utfWritten, v8::String::WriteOptions::NO_NULL_TERMINATION);
        }
        if (targetBytes[0] < 32) {
            memmove(targetBytes + 1, targetBytes, bytesWritten++);
        }
        keySpace.position += bytesWritten;
        mdbKey.mv_size = bytesWritten;
        mdbKey.mv_data = targetBytes;
        return true;
    }

    if (jsKey->IsNumber() || jsKey->IsBigInt()) {
        double number;
        if (jsKey->IsNumber())
            number = Local<Number>::Cast(jsKey)->Value();
        else {
            bool lossless = true;
            number = (double) Local<BigInt>::Cast(jsKey)->Int64Value(&lossless);
            if (!lossless) {
                Nan::ThrowError("BigInt was too large to use as a key.");
                return false;
            }
        }
        uint64_t asInt = *((uint64_t*) &number);
        if (number < 0) {
            asInt = asInt ^ 0x7fffffffffffffff;
            targetBytes[0] = (uint8_t) (asInt >> 60);
        } else {
            targetBytes[0] = (uint8_t) (asInt >> 60) | 0x10;
        }
        // TODO: Use byte_swap to do this faster
        targetBytes[1] = (uint8_t) (asInt >> 52) & 0xff;
        targetBytes[2] = (uint8_t) (asInt >> 44) & 0xff;
        targetBytes[3] = (uint8_t) (asInt >> 36) & 0xff;
        targetBytes[4] = (uint8_t) (asInt >> 28) & 0xff;
        targetBytes[5] = (uint8_t) (asInt >> 20) & 0xff;
        targetBytes[6] = (uint8_t) (asInt >> 12) & 0xff;
        targetBytes[7] = (uint8_t) (asInt >> 4) & 0xff;
        targetBytes[8] = (uint8_t) (asInt << 4) & 0xff;
        if (targetBytes[8] == 0 && !inArray) {
            if (targetBytes[6] == 0 && targetBytes[7] == 0) {
                if (targetBytes[5] == 0 && targetBytes[4] == 0)
                        bytesWritten = 4;
                else
                    bytesWritten = 6;
            } else
                bytesWritten = 8;
        } else
            bytesWritten = 9;
       //fprintf(stdout, "asInt %x %x %x %x %x %x %x %x %x\n", targetBytes[0], targetBytes[1], targetBytes[2], targetBytes[3], targetBytes[4], targetBytes[5], targetBytes[6], targetBytes[7], targetBytes[8]);
    } else if (jsKey->IsArray()) {
        Local<Array> array = Local<Array>::Cast(jsKey);
        int length = array->Length();
        Local<Context> context = Nan::GetCurrentContext();
        int start = keySpace.position;
        MDB_val arrayElement;
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                if (!(targetBytes = keySpace.getTarget(1)))
                    return false;
                targetBytes[0] = 0;
                keySpace.position++;
            }
            if (!valueToKey(array->Get(context, i).ToLocalChecked(), arrayElement, keySpace, true))
                return false;
        }
        bytesWritten = keySpace.position - start;
        targetBytes = &keySpace.data[start]; // retrieve target bytes from the start
    } else if (jsKey->IsNullOrUndefined()) {
        targetBytes[0] = 0;
        bytesWritten = 1;
    } else if (jsKey->IsBoolean()) {
        targetBytes[0] = jsKey->IsTrue() ? 7 : 6;
        bytesWritten = 1;
    } else if (node::Buffer::HasInstance(jsKey)) {
        bytesWritten = node::Buffer::Length(jsKey);
        if (inArray) {
            // if it is an array element, it is needs to be copied into the key sapce
            if (!(targetBytes = keySpace.getTarget(bytesWritten)))
                return false;
            memcpy(targetBytes, node::Buffer::Data(jsKey), bytesWritten);
        } else {
            // we can make a special case here and directly use the buffer itself
            mdbKey.mv_data = node::Buffer::Data(jsKey);
            mdbKey.mv_size = bytesWritten;
            return true;
        }
    } else {
        Nan::ThrowError("Invalid type for key.");
        return false;
    }
    keySpace.position += bytesWritten;
    mdbKey.mv_size = bytesWritten;
    mdbKey.mv_data = targetBytes;
    return true;
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
                return Nan::CopyBuffer(
                    (char*)val.mv_data,
                    val.mv_size
                ).ToLocalChecked();
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
        consumed = val.mv_size;
        bool isOneByte = true;
        int8_t* position = ((int8_t*) val.mv_data);
        int8_t* end = position + consumed;
        if (*position == 27) {
            position++; // skip string escape byte
            consumed--;
            val.mv_data = (char*) val.mv_data + 1;
        }
        for (; position < end; position++) {
            if (*position < 1) { // by using signed chars, non-latin is negative and separators are less than 1
                int8_t c = *position;
                if (c < 0) {
                    isOneByte = false;
                } else { // 0, separator
                    consumed = position - ((int8_t*) val.mv_data);
                    break;
                }
            }
        }
        if (isOneByte)
            value = v8::String::NewFromOneByte(Isolate::GetCurrent(), (uint8_t*) val.mv_data, v8::NewStringType::kNormal, consumed).ToLocalChecked();
        else
            value = Nan::New<v8::String>((char*) val.mv_data, consumed).ToLocalChecked();
    }
    if (consumed < size) {
        if (keyBytes[consumed] != 0 && keyBytes[consumed] != 30) {
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
    if (!valueToKey(info[0], key, *fixedKeySpace, false)) {
        return;
    }
    Nan::MaybeLocal<v8::Object> buffer = Nan::CopyBuffer(
            (char*)key.mv_data,
            key.mv_size);
    info.GetReturnValue().Set(buffer.ToLocalChecked());
}

uint8_t* KeySpace::getTarget(int space) {
    if (position + space > size) {
        if (fixedSize) {
            Nan::ThrowError("Key is too large");
            return nullptr;
        } else {
            uint8_t* oldData = data;
            int oldSize = size;
            size = size << 2;
            data = new uint8_t[size];
            memcpy(data, oldData, position);
            delete[] oldData;
        }
    }
    return &data[position];
}
KeySpace::KeySpace(bool fixed) {
    fixedSize = fixed;
    position = 0;
    size = fixed ? 512 : 8192;
    data = new uint8_t[size];
}
KeySpace::~KeySpace() {
    delete[] data;
}
