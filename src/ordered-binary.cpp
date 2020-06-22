#include "node-lmdb.h"
#include <string.h>
#include <stdio.h>

/*
control character types:
1 - metadata
14 - true
15 - false
17 - number <= -2^48
18 - -2^48 < number < 0
19 - 0 <= number < 2^48
20 - 2^48 <= number
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
      //fprintf(stderr, "making key from string");
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
                //fprintf(stderr, "decimal!");
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
            keyBytes[1] = (uint8_t) (integer >> 48u);
            keyBytes[2] = (uint8_t) (integer >> 40u);
            keyBytes[3] = (uint8_t) (integer >> 32u);
            keyBytes[4] = (uint8_t) (integer >> 24u);
            keyBytes[5] = (uint8_t) (integer >> 16u);
            keyBytes[6] = (uint8_t) (integer >> 8u);
            keyBytes[7] = (uint8_t) integer;
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
        size = length > 0 ? length - 1 : 0;
        Local<Context> context = Nan::GetCurrentContext();
        for (unsigned int i = 0; i < length; i++) {
            valueToKey(array->Get(context, i).ToLocalChecked(), segments[i]);
            size += segments[i].mv_size;
        }
        keyBytes = new unsigned char[size];
        int position = 0;
        for (unsigned int i = 0; i < length; i++) {
            memcpy(&keyBytes[position], segments[i].mv_data, segments[i].mv_size);
            position += segments[i].mv_size;
            keyBytes[position++] = 30;
        }
        fprintf(stdout, "created array key size %u %x %x %x", size, keyBytes[0], keyBytes[4], keyBytes[5]);
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
    fprintf(stdout,"read integer %X %X %X %X %X %X %X %X\n", keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3], keyBytes[4], keyBytes[5], keyBytes[6], keyBytes[7]);
    int number;
    switch (controlByte) {
        case 18:
            // negative number
            /*for (let i = 1; i < 7; i++) {
                buffer[i] = buffer[i] ^ 255
            }*/
            // fall through
        case 19: // number
            number = (keyBytes[1] << 48u) | (keyBytes[2] << 40u) | (keyBytes[3] << 32u) | (keyBytes[4] << 24u) | (keyBytes[5] << 16u) | (keyBytes[6] << 8u) | keyBytes[7];
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
        case 1: case 255:// metadata, return next byte as the code
            /*consumed = 2
            value = new Metadata(buffer[1])*/
            break;
        default:
            if (controlByte < 27) {
                Nan::ThrowError("Unknown control byte");
                return Nan::Undefined();
            }
            if (val.mv_size > 40) {
                fprintf(stdout, "big string %u\n", val.mv_size);
            }
            char* separator = (char*) memchr(((char*) val.mv_data) + consumed, 30, val.mv_size - consumed);
            if (separator) {
                fprintf(stdout, "separator %p\n", separator);
                consumed = separator - ((char*) val.mv_data);
                value = Nan::New<v8::String>((char*) val.mv_data, consumed).ToLocalChecked();
            } else {
                consumed = val.mv_size;
                value = Nan::New<v8::String>((char*) val.mv_data, val.mv_size).ToLocalChecked();
            }/*
            if (multipart) {
                consumed = buffer.indexOf(30)
                if (consumed === -1) {
                    strBuffer = buffer
                    consumed = buffer.length
                } else
                    strBuffer = buffer.slice(0, consumed)
            } else
                strBuffer = buffer
            if (strBuffer[strBuffer.length - 1] == 27) {
                // TODO: needs escaping here
                value = strBuffer.toString()
            } else {
                value = strBuffer.toString()
            }*/
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