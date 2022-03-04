#include "lmdb-js.h"
#include <v8.h>
#include <string.h>
#include <stdio.h>
#if ENABLE_V8_API && NODE_VERSION_AT_LEAST(16,6,0)
#if NODE_VERSION_AT_LEAST(17,0,0)
#include "../dependencies/v8/v8-fast-api-calls.h"
#else
#include "../dependencies/v8/v8-fast-api-calls-v16.h"
#endif
#endif

using namespace v8;
#if ENABLE_V8_API
uint32_t getByBinaryFast(Local<v8::Object> receiver_obj,double dwPointer, uint32_t keySize) {
	DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
	return dw->doGetByBinary(keySize);
}

//class NanWrap : public Nan::ObjectWrap {};
void getByBinaryV8(
  const FunctionCallbackInfo<v8::Value>& info) {
	 Isolate* isolate = Isolate::GetCurrent();
    /*Local<v8::Object> instance =
      Local<v8::Object>::Cast(info.This());
    DbiWrap* dw = (DbiWrap*) Nan::ObjectWrap::Unwrap<NanWrap>(instance);
	 */
	DbiWrap* dw = (DbiWrap*) (size_t) info[0]->NumberValue(isolate->GetCurrentContext()).FromJust();
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
    return info.GetReturnValue().Set(v8::Number::New(isolate, data.mv_size));
}
int32_t positionFast(Local<v8::Object> receiver_obj, uint32_t flags, uint32_t offset, uint32_t keySize, uint64_t endKeyAddress) {
	CursorWrap* cw = static_cast<CursorWrap*>(
		receiver_obj->GetAlignedPointerFromInternalField(0));
	DbiWrap* dw = cw->dw;
	dw->getFast = true;
	cw->flags = flags;
	return cw->doPosition(offset, keySize, endKeyAddress);
}
int32_t iterateFast(Local<v8::Object> receiver_obj) {
	CursorWrap* cw = static_cast<CursorWrap*>(
		receiver_obj->GetAlignedPointerFromInternalField(0));
	DbiWrap* dw = cw->dw;
	dw->getFast = true;
	MDB_val key, data;
	int rc = mdb_cursor_get(cw->cursor, &key, &data, cw->iteratingOp);
	return cw->returnEntry(rc, key, data);
}
int32_t writeFast(Local<v8::Object> receiver_obj, uint64_t instructionAddress) {
	EnvWrap* ew = static_cast<EnvWrap*>(
		receiver_obj->GetAlignedPointerFromInternalField(0));
	int rc;
	if (instructionAddress)
		rc = WriteWorker::DoWrites(ew->writeTxn->txn, ew, (uint32_t*)instructionAddress, nullptr);
	else {
		pthread_cond_signal(ew->writingCond);
		rc = 0;
	}
	return rc;
//	if (rc && !(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND))
	//	options.fallback = true;
}
void write(
	const v8::FunctionCallbackInfo<v8::Value>& info) {
	EnvWrap* ew;
	uint64_t instructionAddress;
	int rc;
	if (instructionAddress)
		rc = WriteWorker::DoWrites(ew->writeTxn->txn, ew, (uint32_t*)instructionAddress, nullptr);
	else {
		pthread_cond_signal(ew->writingCond);
		rc = 0;
	}
}


void clearKeptObjects(const FunctionCallbackInfo<v8::Value>& info) {
	#if NODE_VERSION_AT_LEAST(14,0,0)
	v8::Isolate::GetCurrent()->ClearKeptObjects();
	#endif
}
Napi::Value EnvWrap::detachBuffer(const CallbackInfo& info) {
	#if NODE_VERSION_AT_LEAST(12,0,0)
    napi_value buffer = info[0];
    v8::Local<v8::ArrayBuffer> v8Buffer;
    memcpy(&v8Buffer, &buffer, sizeof(buffer));
	v8Buffer->Detach();
	#endif
    return info.Env().Undefined();
}

#endif


#define EXPORT_FAST(exportName, slowName, fastName) {\
	auto fast = CFunction::Make(fastName);\
	exports->Set(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, exportName).ToLocalChecked(), FunctionTemplate::New(\
		  isolate, slowName, Local<v8::Value>(),\
		  Local<Signature>(), 0, ConstructorBehavior::kThrow,\
		  SideEffectType::kHasNoSideEffect, &fast)->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());\
}
#define EXPORT_FUNCTION(exportName, funcName) \
	exports->Set(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, exportName).ToLocalChecked(), FunctionTemplate::New(\
		  isolate, funcName, Local<v8::Value>(),\
		  Local<Signature>(), 0, ConstructorBehavior::kThrow,\
		  SideEffectType::kHasNoSideEffect)->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());

Napi::Value enableDirectV8(const Napi::CallbackInfo& info) {
	fprintf(stderr, "setupV8\n");
	#if ENABLE_V8_API
	Isolate* isolate = Isolate::GetCurrent();
	napi_value exportsValue = info[0];
	bool result;
	Local<v8::Object> exports;
	memcpy(&exports, &exportsValue, sizeof(exportsValue));
	EXPORT_FUNCTION("getByBinary", getByBinaryV8);
	EXPORT_FUNCTION("clearKeptObjects", clearKeptObjects);
	#endif
	return info.Env().Undefined();
}
Napi::Value enableDirectV8Fast(const Napi::CallbackInfo& info) {
	#if ENABLE_V8_API && NODE_VERSION_AT_LEAST(16,6,0)
	Isolate* isolate = Isolate::GetCurrent();
	napi_value exportsValue = info[0];
	bool result;
	Local<v8::Object> exports;
	memcpy(&exports, &exportsValue, sizeof(exportsValue));
	EXPORT_FAST("getByBinary", getByBinaryV8, getByBinaryFast);
	EXPORT_FUNCTION("clearKeptObjects", clearKeptObjects);
	#endif
	return info.Env().Undefined();
}