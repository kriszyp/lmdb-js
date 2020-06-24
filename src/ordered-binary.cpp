#include "node-lmdb.h"
#include <string.h>
#include <stdio.h>

/*
control character types:
1 - metadata
9 - true
10 - false
11 - number <= -2^55
12 - -2^55 < number < -2^23 (8 bytes min)
13 - -2^23 < number < 0 (6 bytes min)
14 - 0 <= number < 2^23  (6 bytes min)
15 - 2^23 <= number < 2^55 (8 bytes min)
16 - 2^55 <= number
27 - used for escaping control bytes in strings
30 - multipart separator
> 31 normal string characters
*/
const long long MAX_24_BITS = 1 << 24u;
const long long MAX_32_BITS = 1 << 32u;
const long long MAX_40_BITS = 1 << 40u;
const long long MAX_48_BITS = 1 << 48u;
/*
* Convert arbitrary scalar values to buffer bytes with type preservation and type-appropriate ordering
*/
argtokey_callback_t valueToKey(Local<Value> &jsKey, MDB_val &mdbKey) {

    if (jsKey->IsString()) {
        /*if (key.charCodeAt(0) < 32) {
            return Buffer.from('\u001B' + key) // escape, if there is a control character that starts it
        }*/
        writeUtf8ToEntry(Local<String>::Cast(jsKey), &mdbKey, 0);
        return ([](MDB_val &key) -> void {
            delete[] (char*)key.mv_data;
        });
        //return Buffer.from(key)
    }
    unsigned char* keyBytes;
    int size;
    if (jsKey->IsNumber()) {
        double number = Local<Number>::Cast(jsKey)->Value();
        bool negative = number < 0;
/*        if (negative) {
            key = -key // do our serialization on the positive form
        }*/
        long long integer = number;
                //fprintf(stderr, "it is a number! %f %d %d", number, integer, MAX_48_BITS);
        if (number <0xffffffffffffff && number > -0xffffffffffffff) {
            if ((double) integer != number) {
                // handle the decimal/mantissa
                fprintf(stderr, "decimal!");
                char mantissaString[50];
                snprintf(mantissaString, 50, "%f", number);
                /*
                let index = 7
                let asString = key.toString() // we operate with string representation to try to preserve non-binary decimal state
                let exponentPosition = asString.indexOf('e')
                let mantissa
                if (exponentPosition > -1) {
                    let exponent = Number(asString.slice(exponentPosition + 2)) - 2
                    let i
                    for (i = 0; i < exponent; i += 2) {
                        bufferArray[index++] = 1 // zeros with continuance bit
                    }
                    asString = asString.slice(0, exponentPosition).replace(/\./, '')
                    if (i == exponent) {
                        asString = '0' + asString
                    }
                } else {
                    asString = asString.slice(asString.indexOf('.') + 1)
                }
                for (var i = 0, l = asString.length; i < l; i += 2) {
                    bufferArray[index++] = Number(asString[i] + (asString[i + 1] || 0)) * 2 + 1
                }
                bufferArray[index - 1]-- // remove the continuation bit on the last one*/
            } else {
                keyBytes = new unsigned char[8];
            }
            keyBytes[0] = negative ? 18 : 19;
            keyBytes[1] = (uint8_t) (integer >> 47u);
            keyBytes[2] = (uint8_t) (integer >> 39u);
            keyBytes[3] = (uint8_t) (integer >> 31u);
            keyBytes[4] = (uint8_t) (integer >> 23u);
            keyBytes[5] = (uint8_t) (integer >> 15u);
            keyBytes[6] = (uint8_t) (integer >> 7u);
            keyBytes[7] = (uint8_t) (integer << 1u);
            size = 8;
/*            if (negative) {
                // two's complement
                for (let i = 1, l = bufferArray.length; i < l; i++) {
                    bufferArray[i] = bufferArray[i] ^ 255
                }
            }*/
        } else {
            return nullptr;
        }
    } else if (jsKey->IsArray()) {
        Local<Array> array = Local<Array>::Cast(jsKey);
        int length = array->Length();
        MDB_val* segments = new MDB_val[length];
        argtokey_callback_t* callbacks = new argtokey_callback_t[length];
        size = length > 0 ? length - 1 : 0;
        Local<Context> context = Nan::GetCurrentContext();
        for (unsigned int i = 0; i < length; i++) {
            auto freeData = valueToKey(array->Get(context, i).ToLocalChecked(), segments[i]);
            callbacks[i] = freeData;
            size += segments[i].mv_size;
        }
        keyBytes = new unsigned char[size];
        int position = 0;
        for (unsigned int i = 0; i < length; i++) {
            memcpy(&keyBytes[position], segments[i].mv_data, segments[i].mv_size);
            position += segments[i].mv_size;
            keyBytes[position++] = 30;
            if (callbacks[i]) {
                callbacks[i](segments[i]);
            }
        }
    } else if (jsKey->IsBoolean()) {
        keyBytes = new unsigned char[1];
        size = 1;
        keyBytes[0] = jsKey->IsTrue() ? 15 : 14;
    } else if (node::Buffer::HasInstance(jsKey)) {
        mdbKey.mv_size = node::Buffer::Length(jsKey);
        mdbKey.mv_data = node::Buffer::Data(jsKey);
        return nullptr;
    } else {
      fprintf(stderr, "Unknown type");
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
    bool hasMore = false;
    int consumed = 0;
    unsigned char* keyBytes = (unsigned char*) val.mv_data;
    int size = val.mv_size;
    unsigned char controlByte = keyBytes[0];
    int number;
    switch (controlByte) {
        case 18:
            // negative number
            /*for (let i = 1; i < 7; i++) {
                buffer[i] = buffer[i] ^ 255
            }*/
            // fall through
        case 19: // number
            number = (keyBytes[1] << 47u) | (keyBytes[2] << 39u) | (keyBytes[3] << 31u) | (keyBytes[4] << 23u) | (keyBytes[5] << 15u) | (keyBytes[6] << 7u) | (keyBytes[7] >> 1u);
            value = Nan::New<Number>(number);
            consumed = 8;
            break;
        case 14: // boolean false
            consumed = 1;
            value = Nan::New<Boolean>(true);
            break;
        case 15: // boolean true
            consumed = 1;
            value = Nan::New<Boolean>(false);
            break;
        default:
            if (controlByte < 27) {
                return Nan::CopyBuffer(
                    (char*)val.mv_data,
                    val.mv_size
                ).ToLocalChecked();
            }
            char* separator = (char*) memchr(((char*) val.mv_data) + consumed, 30, val.mv_size - consumed);
            if (separator) {
                consumed = separator - ((char*) val.mv_data);
                value = Nan::New<v8::String>((char*) val.mv_data, consumed).ToLocalChecked();
            } else {
                consumed = val.mv_size;
                value = Nan::New<v8::String>((char*) val.mv_data, val.mv_size).ToLocalChecked();
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
            for (unsigned int i = 0; i < length; i++) {
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