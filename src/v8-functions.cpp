#include "lmdb-js.h"
#include <v8.h>
#include <string.h>
#include <stdio.h>
#include <node.h>

#if ENABLE_V8_API && NODE_VERSION_AT_LEAST(16,6,0)
#if NODE_VERSION_AT_LEAST(17,0,0)
#include "../dependencies/v8/v8-fast-api-calls.h"
#else
#include "../dependencies/v8/v8-fast-api-calls-v16.h"
#endif
#endif

using namespace v8;
#if ENABLE_V8_API
int32_t getByBinaryFast(Local<v8::Object> receiver_obj, double dwPointer, uint32_t keySize) {
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
	return info.GetReturnValue().Set(v8::Number::New(isolate, dw->doGetByBinary(info[1]->Uint32Value(isolate->GetCurrentContext()).FromJust())));
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
void detachBuffer(const FunctionCallbackInfo<v8::Value>& info) {
	#if NODE_VERSION_AT_LEAST(12,0,0)
	v8::Local<v8::ArrayBuffer> v8Buffer = Local<v8::ArrayBuffer>::Cast(info[0]);
	v8Buffer->Detach();
	#endif
}

#endif


#define EXPORT_FAST(exportName, slowName, fastName) {\
	auto fast = CFunction::Make(fastName);\
	exports->Set(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, exportName, NewStringType::kInternalized).ToLocalChecked(), FunctionTemplate::New(\
			isolate, slowName, Local<v8::Value>(),\
			Local<Signature>(), 0, ConstructorBehavior::kThrow,\
			SideEffectType::kHasNoSideEffect, &fast)->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());\
}
#define EXPORT_FUNCTION(exportName, funcName) \
	exports->Set(isolate->GetCurrentContext(), v8::String::NewFromUtf8(isolate, exportName, NewStringType::kInternalized).ToLocalChecked(), FunctionTemplate::New(\
			isolate, funcName, Local<v8::Value>(),\
			Local<Signature>(), 0, ConstructorBehavior::kThrow,\
			SideEffectType::kHasNoSideEffect)->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());

Napi::Value enableDirectV8(const Napi::CallbackInfo& info) {
	#if ENABLE_V8_API
	Isolate* isolate = Isolate::GetCurrent();
	napi_value exportsValue = info[0];
	bool result;
	Local<v8::Object> exports;
	memcpy(&exports, &exportsValue, sizeof(exportsValue));
	#if NODE_VERSION_AT_LEAST(16,6,1)
	bool useFastApi;
	napi_get_value_bool(info.Env(), info[1], &useFastApi);
	if (useFastApi) {
		EXPORT_FAST("getByBinary", getByBinaryV8, getByBinaryFast);
	} else {
	#endif
	EXPORT_FUNCTION("getByBinary", getByBinaryV8);
	#if NODE_VERSION_AT_LEAST(16,6,1)
	}
	#endif
	EXPORT_FUNCTION("clearKeptObjects", clearKeptObjects);
	EXPORT_FUNCTION("detachBuffer", detachBuffer);
	#endif
	return info.Env().Undefined();
}
