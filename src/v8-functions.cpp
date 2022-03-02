#include "lmdb-js.h"
#include <v8.h>
#include <string.h>
#include <stdio.h>

using namespace v8;
#if ENABLE_V8_API
uint32_t getByBinaryFast(/*Local<Object> receiver_obj,*/double dwPointer, uint32_t keySize) {
	DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
	return dw->doGetByBinary(keySize);
}

//class NanWrap : public Nan::ObjectWrap {};
void getByBinaryV8(
  const FunctionCallbackInfo<v8::Value>& info) {
	 Isolate* isolate = Isolate::GetCurrent();
    /*Local<Object> instance =
      Local<Object>::Cast(info.This());
    DbiWrap* dw = (DbiWrap*) Nan::ObjectWrap::Unwrap<NanWrap>(instance);
	 */
	DbiWrap* dw = (DbiWrap*) (size_t) info[0]->NumberValue(isolate->GetCurrentContext()).FromJust();
	return info.GetReturnValue().Set(v8::Number::New(isolate, 0xffffffff));/*
    char* keyBuffer = dw->ew->keyBuffer;
    MDB_txn* txn = dw->ew->getReadTxn();
    MDB_val key;
    MDB_val data;
    key.mv_size = info[1]->Uint32Value(isolate->GetCurrentContext()).FromJust();
    key.mv_data = (void*) keyBuffer;
    int rc = mdb_get(txn, dw->dbi, &key, &data);
    if (rc) {
        if (rc == MDB_NOTFOUND)
            return info.GetReturnValue().Set(v8::Number::New(isolate, 0xffffffff));
        //else
          //  return throwLmdbError(rc);
    }   
    rc = getVersionAndUncompress(data, dw);
	 valToBinaryFast(data, dw);
    return info.GetReturnValue().Set(v8::Number::New(isolate, data.mv_size));*/
}

#endif

Napi::Value setupV8(const Napi::CallbackInfo& info) {
	fprintf(stderr, "setupV8\n");
	#if ENABLE_V8_API
	fprintf(stderr, "v8 enabled\n");
	Isolate* isolate = Isolate::GetCurrent();
	napi_value dbiPrototypeValue = info[0];
	bool result;
	napi_has_element(info.Env(), dbiPrototypeValue, 2, &result);
	fprintf(stderr, "has 2 %u ", result);
	napi_has_element(info.Env(), dbiPrototypeValue, 4, &result);
	fprintf(stderr, "has 4 %u ", result);
	Local<v8::Object> dbiPrototype;
	memcpy(&dbiPrototype, &dbiPrototypeValue, sizeof(dbiPrototypeValue));
	fprintf(stderr, "has v8 2 %u ", dbiPrototype->Has(isolate->GetCurrentContext(), 2).FromJust());
	fprintf(stderr, "has v8 4 %u ", dbiPrototype->Has(isolate->GetCurrentContext(), 4).FromJust());
	#if ENABLE_FAST_API && NODE_VERSION_AT_LEAST(16,6,0)
	//auto getFast = CFunction::Make(DbiWrap::getByBinaryFast);
	#endif
	dbiPrototype->Set(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, "getByBinary2").ToLocalChecked(), FunctionTemplate::New(
		  isolate, getByBinaryV8, Local<v8::Value>(),
		  Local<Signature>(), 0, ConstructorBehavior::kThrow,
		  SideEffectType::kHasNoSideEffect/*, &getFast*/)->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());
	fprintf(stderr,"done setting");
	/*auto writeFast = CFunction::Make(EnvWrap::writeFast);
	envTpl->PrototypeTemplate()->Set(isolate, "write", FunctionTemplate::New(
		isolate, EnvWrap::write, Local<Value>(),
		Local<Signature>(), 0, ConstructorBehavior::kThrow,
		SideEffectType::kHasNoSideEffect, &writeFast));*/

	#else
	/*DbiWrap::InstanceMethod("getByBinary", FunctionTemplate::New(
		  isolate, DbiWrap::getByBinary, Local<Value>(),
		  Local<Signature>(), 0, ConstructorBehavior::kThrow,
		  SideEffectType::kHasNoSideEffect));
	EnvWrap::InstanceMethod("write", FunctionTemplate::New(
		isolate, EnvWrap::write, Local<Value>(),
		Local<Signature>(), 0, ConstructorBehavior::kThrow,
		SideEffectType::kHasNoSideEffect));*/
	#endif
//	dbiTpl->InstanceTemplate()->SetInternalFieldCount(1);
	return info.Env().Undefined();
}