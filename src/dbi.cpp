#include "lmdb-js.h"
#include <cstdio>

using namespace Napi;

void setFlagFromValue(int *flags, int flag, const char *name, bool defaultValue, Object options);

DbiWrap::DbiWrap(const Napi::CallbackInfo& info) : ObjectWrap<DbiWrap>(info) {
	this->dbi = 0;
	this->keyType = LmdbKeyType::DefaultKey;
	this->compression = nullptr;
	this->isOpen = false;
	this->getFast = false;
	this->ew = nullptr;
	EnvWrap *ew;
	napi_unwrap(info.Env(), info[0], (void**) &ew);
	this->env = ew->env;
	this->ew = ew;
	int flags = info[1].As<Number>();
	char* nameBytes;
	std::string name;
	if (info[2].IsString()) {
		name = info[2].As<String>().Utf8Value();
		nameBytes = (char*) name.c_str();
	} else
		nameBytes = nullptr;
	LmdbKeyType keyType = (LmdbKeyType) info[3].As<Number>().Int32Value();
	Compression* compression;
	if (info[4].IsObject())
		napi_unwrap(info.Env(), info[4], (void**) &compression);
	else
		compression = nullptr;
	int rc = this->open(flags & ~HAS_VERSIONS, nameBytes, flags & HAS_VERSIONS,
		keyType, compression);
	//if (nameBytes)
		//delete nameBytes;
	if (rc) {
		if (rc == MDB_NOTFOUND)
			this->dbi = (MDB_dbi) 0xffffffff;
		else {
			//delete this;
			throwLmdbError(info.Env(), rc);
			return;
		}
	}
	info.This().As<Object>().Set("dbi", Number::New(info.Env(), this->dbi));
	info.This().As<Object>().Set("address", Number::New(info.Env(), (size_t) this));
}


DbiWrap::~DbiWrap() {
	// Imagine the following JS:
	// ------------------------
	//	 var dbi1 = env.openDbi({ name: "hello" });
	//	 var dbi2 = env.openDbi({ name: "hello" });
	//	 dbi1.close();
	//	 txn.putString(dbi2, "world");
	// -----
	// The above DbiWrap objects would both wrap the same MDB_dbi, and if closing the first one called mdb_dbi_close,
	// that'd also render the second DbiWrap instance unusable.
	//
	// For this reason, we will never call mdb_dbi_close
	// NOTE: according to LMDB authors, it is perfectly fine if mdb_dbi_close is never called on an MDB_dbi
}


int DbiWrap::open(int flags, char* name, bool hasVersions, LmdbKeyType keyType, Compression* compression) {
	MDB_txn* txn = ew->getReadTxn();
	this->hasVersions = hasVersions;
	this->compression = compression;
	this->keyType = keyType;
	this->flags = flags;
	flags &= ~HAS_VERSIONS;
	int rc = mdb_dbi_open(txn, name, flags, &this->dbi);
	if (rc)
		return rc;
	this->isOpen = true;
	if (keyType == LmdbKeyType::DefaultKey && name) { // use the fast compare, but can't do it if we have db table/names mixed in
		mdb_set_compare(txn, dbi, compareFast);
	}
	return 0;
}
extern "C" EXTERN uint32_t getDbi(double dw) {
	return (uint32_t) ((DbiWrap*) (size_t) dw)->dbi;
}

Value DbiWrap::close(const Napi::CallbackInfo& info) {
	if (this->isOpen) {
		mdb_dbi_close(this->env, this->dbi);
		this->isOpen = false;
		this->ew = nullptr;
	}
	else {
		return throwError(info.Env(), "The Dbi is not open, you can't close it.");
	}
	return info.Env().Undefined();
}

Value DbiWrap::drop(const Napi::CallbackInfo& info) {
	int del = 1;
	int rc;
	if (!this->isOpen) {
		return throwError(info.Env(), "The Dbi is not open, you can't drop it.");
	}

	// Check if the database should be deleted
	if (info.Length() == 1 && info[0].IsObject()) {
		Napi::Object options = info[0].As<Object>();
		
		// Just free pages
		Napi::Value opt = options.Get("justFreePages");
		del = opt.IsBoolean() ? !opt.As<Boolean>().Value() : 1;
	}

	// Drop database
	rc = mdb_drop(ew->writeTxn->txn, dbi, del);
	if (rc != 0) {
		return throwLmdbError(info.Env(), rc);
	}

	// Only close database if del == 1
	if (del == 1) {
		isOpen = false;
		ew = nullptr;
	}
	return info.Env().Undefined();
}

Value DbiWrap::stat(const Napi::CallbackInfo& info) {
	MDB_stat stat;
	mdb_stat(this->ew->getReadTxn(), dbi, &stat);
	Object stats = Object::New(info.Env());
	stats.Set("pageSize", Number::New(info.Env(), stat.ms_psize));
	stats.Set("treeDepth", Number::New(info.Env(), stat.ms_depth));
	stats.Set("treeBranchPageCount", Number::New(info.Env(), stat.ms_branch_pages));
	stats.Set("treeLeafPageCount", Number::New(info.Env(), stat.ms_leaf_pages));
	stats.Set("entryCount", Number::New(info.Env(), stat.ms_entries));
	stats.Set("overflowPages", Number::New(info.Env(), stat.ms_overflow_pages));
	return stats;
}

extern "C" EXTERN int32_t dbiGetByBinary(double dwPointer, uint32_t keySize) {
	DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
	return dw->doGetByBinary(keySize);
}
extern "C" EXTERN int64_t openCursor(double dwPointer) {
	DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
	MDB_cursor *cursor;
	MDB_txn *txn = dw->ew->getReadTxn();
	int rc = mdb_cursor_open(txn, dw->dbi, &cursor);
	if (rc)
		return rc;
	CursorWrap* cw;// = new CursorWrap(cursor);
	cw->keyType = dw->keyType;
	cw->dw = dw;
	cw->txn = txn;
	return (int64_t) cw;
}


int32_t DbiWrap::doGetByBinary(uint32_t keySize) {
	char* keyBuffer = ew->keyBuffer;
	MDB_txn* txn = ew->getReadTxn();
	MDB_val key, data;
	key.mv_size = keySize;
	key.mv_data = (void*) keyBuffer;

	int result = mdb_get(txn, dbi, &key, &data);
	if (result) {
        if (result > 0)
            return -result;
		return result;
	}
	result = getVersionAndUncompress(data, this);
	if (result)
		valToBinaryFast(data, this);
	if (data.mv_size < 0x80000000)
		return data.mv_size;
	*((uint32_t*)keyBuffer) = data.mv_size;
	return -30000;
	/*
	alternately, if we want to send over the address, which can be used for direct access to the LMDB shared memory, but all benchmarking shows it is slower
	*((size_t*) keyBuffer) = data.mv_size;
	*((uint64_t*) (keyBuffer + 8)) = (uint64_t) data.mv_data;
	return 0;*/
}

NAPI_FUNCTION(getByBinary) {
	ARGS(2)
	DbiWrap* dw;
	GET_INT64_ARG(dw, 0);
	uint32_t keySize;
	GET_UINT32_ARG(keySize, 1);
	RETURN_INT32(dw->doGetByBinary(keySize));
}
napi_finalize noop = [](napi_env, void *, void *) {
	// Data belongs to LMDB, we shouldn't free it here
};
Value DbiWrap::getSharedByBinary(const Napi::CallbackInfo& info) {
	char* keyBuffer = this->ew->keyBuffer;
	MDB_txn* txn = this->ew->getReadTxn();
	MDB_val key;
	MDB_val data;
	key.mv_size = info[0].As<Number>().Uint32Value();
	key.mv_data = (void*) keyBuffer;
	int rc = mdb_get(txn, this->dbi, &key, &data);
	if (rc) {
		if (rc == MDB_NOTFOUND)
			return info.Env().Undefined();
		else
			return throwLmdbError(info.Env(), rc);
	}
	rc = getVersionAndUncompress(data, this);
	napi_value buffer;
	napi_create_external_buffer(info.Env(), data.mv_size,
		(char*) data.mv_data, noop, nullptr, &buffer);
	return Value::From(info.Env(), buffer);
}

Value DbiWrap::getStringByBinary(const Napi::CallbackInfo& info) {
	char* keyBuffer = this->ew->keyBuffer;
	MDB_txn* txn = this->ew->getReadTxn();
	MDB_val key;
	MDB_val data;
	key.mv_size = info[0].As<Number>().Uint32Value();
	key.mv_data = (void*) keyBuffer;
	int rc = mdb_get(txn, this->dbi, &key, &data);
	if (rc) {
		if (rc == MDB_NOTFOUND)
			return info.Env().Undefined();
		else
			return throwLmdbError(info.Env(), rc);
	}
	rc = getVersionAndUncompress(data, this);
	if (rc)
		return valToUtf8(info.Env(), data);
	else
		return Number::New(info.Env(), data.mv_size);
}

extern "C" EXTERN int prefetch(double dwPointer, double keysPointer) {
	DbiWrap* dw = (DbiWrap*) (size_t) dwPointer;
	return dw->prefetch((uint32_t*)(size_t)keysPointer);
}

int DbiWrap::prefetch(uint32_t* keys) {
	MDB_txn* txn;
	mdb_txn_begin(ew->env, nullptr, MDB_RDONLY, &txn);
	MDB_val key;
	MDB_val data;
	unsigned int flags;
	mdb_dbi_flags(txn, dbi, &flags);
	bool dupSort = flags & MDB_DUPSORT;
	int effected = 0;
	MDB_cursor *cursor;
	int rc = mdb_cursor_open(txn, dbi, &cursor);
	if (rc)
		return rc;
	while((key.mv_size = *keys++) > 0) {
		if (key.mv_size == 0xffffffff) {
			// it is a pointer to a new buffer
			keys = (uint32_t*) (size_t) *((double*) keys); // read as a double pointer
			key.mv_size = *keys++;
			if (key.mv_size == 0)
				break;
		}
		key.mv_data = (void*) keys;
		keys += (key.mv_size + 12) >> 2;
		int rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_KEY);
		while (!rc) {
			// access one byte from each of the pages to ensure they are in the OS cache,
			// potentially triggering the hard page fault in this thread
			int pages = (data.mv_size + 0xfff) >> 12;
			// TODO: Adjust this for the page headers, I believe that makes the first page slightly less 4KB.
			for (int i = 0; i < pages; i++) {
				effected += *(((uint8_t*)data.mv_data) + (i << 12));
			}
			if (dupSort) // in dupsort databases, access the rest of the values
				rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT_DUP);
			else
				rc = 1; // done
		}
	}
	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
	return effected;
}

class PrefetchWorker : public AsyncWorker {
  public:
	PrefetchWorker(DbiWrap* dw, uint32_t* keys, const Function& callback)
	  : AsyncWorker(callback), dw(dw), keys(keys) {}

	void Execute() {
		dw->prefetch(keys);
	}

	void OnOK() {
		Callback().Call({Env().Null()});
	}

  private:
	DbiWrap* dw;
	uint32_t* keys;
};

Value DbiWrap::prefetch(const Napi::CallbackInfo& info) {
	size_t keysAddress = info[0].As<Number>().Int64Value();
	PrefetchWorker* worker = new PrefetchWorker(this, (uint32_t*) keysAddress, info[1].As<Function>());
	worker->Queue();
	return info.Env().Undefined();
}

void DbiWrap::setupExports(Napi::Env env, Object exports) {
	Function DbiClass = DefineClass(env, "Dbi", {
		// DbiWrap: Prepare constructor template
		// DbiWrap: Add functions to the prototype
		DbiWrap::InstanceMethod("close", &DbiWrap::close),
		DbiWrap::InstanceMethod("drop", &DbiWrap::drop),
		DbiWrap::InstanceMethod("stat", &DbiWrap::stat),
		DbiWrap::InstanceMethod("getStringByBinary", &DbiWrap::getStringByBinary),
		DbiWrap::InstanceMethod("getSharedByBinary", &DbiWrap::getSharedByBinary),
		DbiWrap::InstanceMethod("prefetch", &DbiWrap::prefetch),
	});
	exports.Set("Dbi", DbiClass);
	EXPORT_NAPI_FUNCTION("getByBinary", getByBinary);
	// TODO: wrap mdb_stat too
}

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

