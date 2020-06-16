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
const long long MAX_24_BITS = 1 << 24;
const long long MAX_32_BITS = 1 << 32;
const long long MAX_40_BITS = 1 << 40;
const long long MAX_48_BITS = 1 << 48;
/*
* Convert arbitrary scalar values to buffer bytes with type preservation and type-appropriate ordering
*/
argtokey_callback_t valueToKey(Local<Value> &jsKey, MDB_val &mdbKey) {

    if (jsKey->IsString()) {
      fprintf(stderr, "making key from string");
        /*if (key.charCodeAt(0) < 32) {
            return Buffer.from('\u001B' + key) // escape, if there is a control character that starts it
        }*/
        CustomExternalStringResource::writeTo(Local<String>::Cast(jsKey), &mdbKey);
        return ([](MDB_val &key) -> void {
            delete[] (char*)key.mv_data;
        });
        //return Buffer.from(key)
    }
    char* keyBytes;
    int size;
    if (jsKey->IsNumber()) {
        double number = Local<Number>::Cast(jsKey)->Value();
        bool negative = number < 0;
/*        if (negative) {
            key = -key // do our serialization on the positive form
        }*/
        long long integer = number;
                fprintf(stderr, "it is a number! %f %d %d", number, integer, MAX_48_BITS);
        if (number <100000000000000 && number > -100000000000000) {
            if ((double) integer != number) {
                // handle the decimal/mantissa
                fprintf(stderr, "decimal!");
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
              fprintf(stderr,"integer ");
                keyBytes = new char[8];
            }
            memcpy(keyBytes + 1, &integer + 2, 6);
            keyBytes[0] = negative ? 18 : 19;
/*            if (negative) {
                // two's complement
                for (let i = 1, l = bufferArray.length; i < l; i++) {
                    bufferArray[i] = bufferArray[i] ^ 255
                }
            }*/
        } else {
            return nullptr;
        }
    } else if (jsKey->IsBoolean()) {
        char* keyBytes = new char[1];
        size = 1;
        keyBytes[0] = jsKey->IsTrue() ? 15 : 14;
    } else if (node::Buffer::HasInstance(jsKey)) {
        fprintf(stderr, "is Buffer");
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
    do {
        int consumed;
        char controlByte = ((char*) val.mv_data)[0];
        int number = 0;
        switch (controlByte) {
            case 18:
                // negative number
                /*for (let i = 1; i < 7; i++) {
                    buffer[i] = buffer[i] ^ 255
                }*/
                // fall through
            case 19: // number
                
                memcpy(&number + 2, (char*) val.mv_data + 1, 6);
                value = Nan::New<Number>(number);
                consumed = 6;
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
                
                char* separator = (char*) memchr(((char*) val.mv_data) + consumed, 30, val.mv_size - consumed);
                if (separator) {
                    value = Nan::New<v8::String>((char*) val.mv_data, separator - ((char*) val.mv_data)).ToLocalChecked();
                } else {
                    value = Nan::New<v8::String>((char*) val.mv_data, separator - ((char*) val.mv_data)).ToLocalChecked();
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
        }/*
        if (multipart) {
            if (!values) {
                values = [value]
            } else {
                values.push(value)
            }
            if (buffer.length === consumed) {
                return values // done, consumed all the values
            }
            if (buffer[consumed] !== 30) {
                Nan::ThrowError("Invalid separator byte");
                return Nan::Undefined();

            }
            buffer = buffer.slice(consumed + 1)
        }*/
    } while (hasMore);
    // single value mode
    return value;
}