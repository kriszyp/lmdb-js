/* write instructions

0-3 flags
	1 - put with pointer  - 16 + key + 8? + 8? + 8
	8 - put inline

	2 - del - 16 + key + 8?
	3 - del with value
	3 - start block - 16 + key + 8
	4 - user callback - 8 bytes long
	5 - drop - 8 bytes long
	7 - block end - 8 bytes long
	15 - pointer to next instruction  - 16 bytes long
	0x100 - conditional based on version
	0x200 - version included
	0x400 - compressible
	0x800 - put value is inline (otherwise pointer)?

4-7 dbi
8-11 key-size
12 ... key followed by at least 2 32-bit zeros
4 value-size
8 bytes: value pointer (or value itself)
8 next-compressible pointer?
8 compressor pointer?
8 bytes (optional): conditional version
8 bytes (optional): version
inline value?
*/
#include "node-lmdb.h"
#ifndef _WIN32
#include <stdatomic.h>
#endif
// flags:
const int NO_INSTRUCTION_YET = 0;
const int PUT = 15;
const int DEL = 13;
const int DEL_VALUE = 14;
const int START_CONDITION_BLOCK = 4;
const int START_CONDITION_VALUE_BLOCK = 6;
const int START_BLOCK = 1;
const int BLOCK_END = 2;
const int POINTER_NEXT = 3;
const int USER_CALLBACK = 8;
const int USER_CALLBACK_STRICT_ORDER = 0x100000;
const int DROP_DB = 12;
const int HAS_KEY = 4;
const int HAS_VALUE = 2;
const int CONDITIONAL = 8;
const int CONDITIONAL_VERSION = 0x100;
const int SET_VERSION = 0x200;
const int HAS_INLINE_VALUE = 0x400;
const int COMPRESSIBLE = 0x100000;
const int DELETE_DATABASE = 0x400;
const int TXN_HAD_ERROR = 0x80000000;
const int TXN_DELIMITER = 0x20000000;
const int TXN_COMMITTED = 0x40000000;
const int WAITING_OPERATION = 0x400000;
const int IF_NO_EXISTS = MDB_NOOVERWRITE; //0x10;
// result codes:
const int LOCKED = 0x200000;
const int FAILED_CONDITION = 1;
const int FINISHED_OPERATION = 0x10000000;
const int BATCH_DELIMITER = 0x8000000;
const int BAD_KEY = 3;
const int NOT_FOUND = 1;


WriteWorker::~WriteWorker() {
	uv_mutex_destroy(userCallbackLock);
	uv_cond_destroy(userCallbackCond);	
}
void WriteWorker::ContinueWrite(int rc, bool hasStarted) {
	fprintf(stdout, "continueWrite %u\n", rc);
	if (hasStarted) {
		finishedProgress = true;
		currentTxnWrap = envForTxn->currentWriteTxn;
	}
	if (rc == 4)
		uv_mutex_lock(userCallbackLock);
	envForTxn->currentWriteTxn = nullptr;
	interruptionStatus = rc;
	fprintf(stdout, "continueWrite signal %p\n", this);
	uv_cond_signal(userCallbackCond);
	fprintf(stdout, "continue unlock\n");
	uv_mutex_unlock(userCallbackLock);
}

WriteWorker::WriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions, double* nextCompressibleArg, Nan::Callback *callback)
		: Nan::AsyncProgressWorker(callback, "lmdb:write"),
		env(env),
		envForTxn(envForTxn),
		instructions(instructions),
		nextCompressible(nextCompressibleArg) {
	//fprintf(stdout, "nextCompressibleArg %p\n", nextCompressibleArg);
		interruptionStatus = 0;
		currentTxnWrap = nullptr;
		userCallbackLock = new uv_mutex_t;
		userCallbackCond = new uv_cond_t;
		uv_mutex_init(userCallbackLock);
		uv_cond_init(userCallbackCond);
	}
double* WriteWorker::CompressOne(double* nextCompressible) {
	MDB_val value;
	uint64_t nextCompressibleSlot;
	Compression* compression;
	uint64_t compressionPointer;
#ifdef _WIN32
	compressionPointer = InterlockedExchange64((int64_t*)nextCompressible + 1, 0);
#else
	compressionPointer = atomic_fetch_exchange(compressible, 0);
#endif
	compression = (Compression*)(size_t) * ((double*)&compressionPointer);
	if (compression) {
		value.mv_data = (void*)((size_t) * (nextCompressible - 1));
		value.mv_size = *(((uint32_t*)nextCompressible) - 3);
		fprintf(stdout, "compressing %p %p %u\n", compression, value.mv_data, value.mv_size);
		void* compressedData = compression->compress(&value, nullptr);
		if (compressedData) {
			*((size_t*)(nextCompressible - 1)) = (size_t)value.mv_data;
			*(((uint32_t*)nextCompressible) - 3) = value.mv_size;
			fprintf(stdout, "compressed to %p %u\n", value.mv_data, value.mv_size);
		} else
			fprintf(stdout, "failed to compress\n");
		WakeByAddressAll(nextCompressible);
	}
/*
#ifdef _WIN32
	nextCompressibleSlot = InterlockedExchange64((int64_t*)nextCompressible, 0xffffffffffffffffll);
#else
	nextCompressibleSlot = atomic_fetch_exchange(compressible, 0xffffffffffffffffll);
#endif*/
	return (double*)(size_t) * (nextCompressible + 1);
}


void WriteWorker::Compress() {
	fprintf(stdout, "compress\n");
	while (nextCompressible) {
		nextCompressible = CompressOne(nextCompressible);
	}
}

void WriteWorker::Execute(const ExecutionProgress& executionProgress) {
	this->executionProgress = (ExecutionProgress*) &executionProgress;
	if (nextCompressible)
		Compress();
	Write();
}
MDB_txn* WriteWorker::AcquireTxn(bool onlyPaused) {
	fprintf(stdout, "acquire lock\n");
	uv_mutex_lock(userCallbackLock);
	MDB_txn* txn = envForTxn->currentBatchTxn;
	return txn;
}
int WriteWorker::WaitForCallbacks(MDB_txn** txn) {
waitForCallback:
	int rc;
	//fprintf(stdout, "wait for callback %p\n", this);
	if (interruptionStatus == 0 && !finishedProgress)
		uv_cond_wait(userCallbackCond, userCallbackLock);
	//fprintf(stdout, "callback done waiting\n");
	if (interruptionStatus != 0 && !finishedProgress) {
		if (interruptionStatus == INTERRUPT_BATCH) { // interrupted by JS code that wants to run a synchronous transaction
			rc = mdb_txn_commit(*txn);
			if (rc == 0) {
				// wait again until the sync transaction is completed
				uv_cond_wait(userCallbackCond, userCallbackLock);
				// now restart our transaction
				rc = mdb_txn_begin(env, nullptr, 0, txn);
				envForTxn->currentBatchTxn = *txn;
				interruptionStatus = 0;
				uv_cond_signal(userCallbackCond);
				goto waitForCallback;
			}
			if (rc != 0) {
				fprintf(stdout, "wfc unlock\n");
				return rc;
			}
		}
	}
}

void WriteWorker::Write() {
	MDB_txn *txn;
	MDB_val key, value;
	uint32_t* instruction = instructions;
	uint32_t* lastStart;
	int rc, txnId;
	bool moreProcessing = true;
	finishedProgress = true;
	bool compressed;
	// we do compression in this thread to offload from main thread, but do it before transaction to minimize time that the transaction is open
	do {
		int conditionDepth = 0;
		if (callback) {
			rc = mdb_txn_begin(env, nullptr, 0, &txn);
			txnId = mdb_txn_id(txn);
			if (rc != 0) {
				return SetErrorMessage(mdb_strerror(rc));
			}
		} else{
			txn = envForTxn->currentWriteTxn->txn;
		}
		if (envForTxn) {
			envForTxn->currentBatchTxn = txn;
		}
		int validatedDepth = 0;
		double conditionalVersion, setVersion;
		bool startingTransaction = true;
		do {
			uv_mutex_lock(userCallbackLock);
next_inst:	uint32_t* start = instruction++;
			uint32_t flags = *start;
			MDB_dbi dbi;
			bool validated = conditionDepth == validatedDepth;
			if (flags & HAS_KEY) {
				// a key based instruction, get the key
				dbi = (MDB_dbi) *instruction++;
				key.mv_size = *instruction++;
				key.mv_data = instruction;
				instruction = (uint32_t*) (((size_t) instruction + key.mv_size + 16) & (~7));
				if (flags & HAS_VALUE) {
					value.mv_size = *(instruction - 1);
					if (flags & COMPRESSIBLE) {
						uint32_t highPointer = *(instruction + 1);
						if (highPointer > 0x40000000) { // not compressed yet
/*							Compression* compression;
							// this is the algorithm for always compressing if it is not compressed yet (rather than waiting for the other thread)
#ifdef _WIN32
							compression = (Compression*)InterlockedExchange64((int64_t*)(instruction + 4), 0);
#else
							compression = atomic_fetch_exchange(instruction + 4, 0);
#endif
							if (compression) {
								CompressOne((double*)(instruction + 2));
							} // else it is already done now */
							CompressOne((double*)(instruction + 2));
							while(*(instruction + 1) > 0x40000000) {
								// compression in progress
								WaitOnAddress(instruction, &highPointer, 4, INFINITE);
								//syscall(SYS_futex, instruction + 2, FUTEX_WAIT, compressionPointer, NULL, NULL, 0);
							}
						}
						// compressed
						value.mv_data = (void*)(size_t) * ((size_t*)instruction);
						instruction += 6; // skip compression pointers
						compressed = true;
					} else {
						value.mv_data = (void*)(size_t) * ((double*)instruction);
						instruction += 2;
					}
				}
				if (flags & CONDITIONAL_VERSION) {
					conditionalVersion = *((double*) instruction);
					instruction += 2;
					rc = mdb_get(txn, dbi, &key, &value);
					if (rc)
						validated = false;
					else
						validated = validated && conditionalVersion == *((double*)value.mv_data);
				}
				if (flags & SET_VERSION) {
					setVersion = *((double*) instruction);
					instruction += 2;
				}
				if ((flags & IF_NO_EXISTS) && (flags & START_CONDITION_BLOCK)) {
					rc = mdb_get(txn, dbi, &key, &value);
					validated = validated && rc == MDB_NOTFOUND;
				}
			} else
				instruction++;
			//fprintf(stdout, "instr flags %p %p %u\n", start, flags, conditionDepth);
			if (validated || !(flags & CONDITIONAL)) {
				switch (flags & 0xf) {
				case NO_INSTRUCTION_YET:
					instruction -= 2; // reset back to the previous flag as the current instruction
					int previousFlags;
					// we use memory fencing here to make sure all reads and writes are ordered
#ifdef _WIN32
					previousFlags = InterlockedOr((LONG*)lastStart, (LONG) LOCKED);
#else
					previousFlags = atomic_fetch_or(lastStart, LOCKED);
#endif
					rc = 0;
					if (!*start && (!finishedProgress || conditionDepth)) {
						*lastStart = (previousFlags & ~LOCKED) | WAITING_OPERATION;
						fprintf(stderr, "write thread waiting %p\n", lastStart);
						WaitForCallbacks(&txn);
					}
					if (*start) {
						//fprintf(stderr, "now there is a value available %p\n", *start);
						// the value changed while we were locking or waiting, clear the flags, we are back to running through instructions
						*lastStart = (previousFlags & 0xf) | FINISHED_OPERATION;
						goto next_inst;
					}
					// still nothing to do, end the transaction
					*lastStart = (previousFlags & 0xf) | FINISHED_OPERATION | TXN_DELIMITER;
					//fprintf(stderr, "calling the txn down %p\n", lastStart);
					uv_mutex_unlock(userCallbackLock);
					goto txn_done;
				case BLOCK_END:
					rc = !validated;
					conditionDepth--;
					if (validatedDepth > conditionDepth)
						validatedDepth--;
					goto next_inst;
				case PUT:
					if (flags & SET_VERSION)
						rc = putWithVersion(txn, dbi, &key, &value, flags & (MDB_NOOVERWRITE | MDB_NODUPDATA | MDB_APPEND | MDB_APPENDDUP), setVersion);
					else
						rc = mdb_put(txn, dbi, &key, &value, flags & (MDB_NOOVERWRITE | MDB_NODUPDATA | MDB_APPEND | MDB_APPENDDUP));
					if ((flags & COMPRESSIBLE) && compressed)
						free(value.mv_data);
					//fprintf(stdout, "put %u \n", key.mv_size);
					break;
				case DEL:
					rc = mdb_del(txn, dbi, &key, nullptr);
					break;
				case DEL_VALUE:
					rc = mdb_del(txn, dbi, &key, &value);
					if ((flags & COMPRESSIBLE) && compressed)
						free(value.mv_data);
					break;
				case START_BLOCK: case START_CONDITION_BLOCK:
					rc = !validated;
					if (validated)
						validatedDepth++;
					conditionDepth++;
					break;
				case USER_CALLBACK:
					finishedProgress = false;
					progressStatus = 2;
					executionProgress->Send(nullptr, 0);
					if (flags & USER_CALLBACK_STRICT_ORDER)
						WaitForCallbacks(&txn);
					break;
				case DROP_DB:
					rc = mdb_drop(txn, dbi, (flags & DELETE_DATABASE) ? 1 : 0);
					break;
				case POINTER_NEXT:
					instruction = (uint32_t*)(size_t) * ((double*)instruction);
					goto next_inst;
				default:
					fprintf(stderr, "Unknown flags %p\n", flags);
				}
				if (rc) {
					if (!(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND))
						fprintf(stderr, "Unknown return code %i", rc);
					flags = FINISHED_OPERATION | FAILED_CONDITION;
				}
				else
					flags = FINISHED_OPERATION;
			} else
				flags = FINISHED_OPERATION | FAILED_CONDITION;
			lastStart = start;
			*start = flags;
			uv_mutex_unlock(userCallbackLock);
		} while(callback); // keep iterating in async/multiple-instruction mode, just one instruction in sync mode
txn_done:
		if (envForTxn) {
			envForTxn->currentBatchTxn= nullptr;
			if (currentTxnWrap) {
				// if a transaction was wrapped, need to do clean up
				currentTxnWrap->removeFromEnvWrap();
			}
		}
		if (callback) {
			/*if (rc) // are there any return codes that would lead us to abort?
				mdb_txn_abort(txn);
			else*/
			rc = mdb_txn_commit(txn);
			//fprintf(stdout, "committed %p\n", instruction);

			if (rc == 0) {
				unsigned int envFlags;
				mdb_env_get_flags(env, &envFlags);
				if (envFlags & MDB_OVERLAPPINGSYNC) {
					// successfully completed, we can now send a progress event to tell JS that the commit has been completed
					// and that it is welcome to submit the next transaction, however the commit is not synced/flushed yet,
					// so we continue execution to do that
					progressStatus = 1;
					executionProgress->Send(nullptr, 0);
					//envForTxn->syncTxnId = txnId;
					rc= mdb_env_sync(env, 1);
					// signal a subsequent txn that we are synced
					//uv_cond_signal(envForTxn->syncCond);
					if (rc)
						return SetErrorMessage(mdb_strerror(rc));
					// we have sync'ed to disk, but the commit is not truly durable and available on restart yet since
					// we always use the previous snapshot/txn, so we need to wait for completion of next transaction
					// if (ongoing transaction)
					// 	uv_cond_wait(envForTxn->txnCond);
					// else // we start an empty txn to ensure this txn becomes the previous one
					// the drawback to beginning a transaction as confirmation is that if other processes are doing multiple/large
					// transactions, we could have a long wait here, and it is potentially better to do this in a separate thread and
					// also poll for txn id increments that would indicate that the commit is truly durable.
					// we also don't want to be too jumpy about making empty transactions, certainly preferable that we
					// simply use the next transaction as confirmation of durability
					rc = mdb_txn_begin(env, nullptr, 0, &txn);
					int nextTxnId = mdb_txn_id(txn);
					if (nextTxnId - 2 >= txnId) {
						// if there has already been another transaction completed, we are truly done, abort the empty txn
						mdb_txn_abort(txn);
					}
					mdb_txn_commit(txn);
				}
			} else {
				return SetErrorMessage(mdb_strerror(rc));
			}
			if (*instruction) {
				*lastStart |= TXN_COMMITTED;
			} else {
				int previousFlags;
				// we use memory fencing here to make sure all reads and writes are ordered
#ifdef _WIN32
				previousFlags = InterlockedOr((LONG*) lastStart, LOCKED | TXN_COMMITTED);
#else
				previousFlags = atomic_fetch_or(lastStart, LOCKED | TXN_COMMITTED);
#endif
				if (*instruction) // changed while we were locking, keep running
					*lastStart = (previousFlags & 0xf) | FINISHED_OPERATION | TXN_DELIMITER | TXN_COMMITTED;
				else { // really done with the batch
					*lastStart = (previousFlags & 0xf) | FINISHED_OPERATION | BATCH_DELIMITER | TXN_DELIMITER | TXN_COMMITTED;
					moreProcessing = false;
				}
			}
		} else { // sync mode
			interruptionStatus = 0;
			return;
		}
		if (moreProcessing) {
			*instruction |= TXN_DELIMITER;
			progressStatus = 1;
			executionProgress->Send(nullptr, 0);
		}
	} while(moreProcessing);
}

void WriteWorker::HandleProgressCallback(const char* data, size_t count) {
	Nan::HandleScope scope;
	if (interruptionStatus != 0) {
		fprintf(stdout, "progress lock\n");
		uv_mutex_lock(userCallbackLock);
		fprintf(stdout, "progress got lock\n");
		if (interruptionStatus != 0)
			uv_cond_wait(userCallbackCond, userCallbackLock);
		// aquire the lock so that we can ensure that if it is restarting the transaction, it finishes doing that
		fprintf(stdout, "progress unlock\n");
		uv_mutex_unlock(userCallbackLock);
	}
	v8::Local<v8::Value> argv[] = {
		Nan::New<Number>(progressStatus)
	};
	envForTxn->currentWriteTxn = currentTxnWrap;
	bool immediateContinue = callback->Call(1, argv, async_resource).ToLocalChecked()->IsTrue();
	if (immediateContinue)
		ContinueWrite(0, true);
}

void WriteWorker::HandleOKCallback() {
	Nan::HandleScope scope;
	Local<v8::Value> argv[] = {
		Nan::New<Number>(0)
	};
	if (envForTxn->writeWorker == this)
		envForTxn->writeWorker = nullptr;
	callback->Call(1, argv, async_resource);
}

NAN_METHOD(EnvWrap::startWriting) {
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }
    size_t instructionAddress = Local<Number>::Cast(info[0])->Value();
    size_t nextCompressible = Local<Number>::Cast(info[1])->Value();
    Nan::Callback* callback = new Nan::Callback(Local<v8::Function>::Cast(info[2]));

    WriteWorker* worker = new WriteWorker(ew->env, ew, (uint32_t*) instructionAddress, (double*) nextCompressible, callback);
	ew->writeWorker = worker;
    Nan::AsyncQueueWorker(worker);
}


#ifdef ENABLE_FAST_API
void EnvWrap::writeFast(Local<Object> receiver_obj, uint64_t instructionAddress, FastApiCallbackOptions& options) {
	EnvWrap* cw = static_cast<EnvWrap*>(
		receiver_obj->GetAlignedPointerFromInternalField(0));
	size_t instructionAddress = Local<Number>::Cast(info[0])->Value();
	WriteWorker* syncWriter = ew->syncWriter;
	if (!syncWriter)
		syncWriter = ew->syncWriter = new WriteWorker(ew->env, ew, (uint32_t*)instructionAddress, nullptr, nullptr);
	syncWriter->Write();
	if (syncWriter.interruptionStatus)
		options.fallback = true;
}
#endif
void EnvWrap::write(
	const v8::FunctionCallbackInfo<v8::Value>& info) {
	v8::Local<v8::Object> instance =
		v8::Local<v8::Object>::Cast(info.Holder());
	EnvWrap* ew = Nan::ObjectWrap::Unwrap<EnvWrap>(instance);
	if (!ew->env) {
		return Nan::ThrowError("The environment is already closed.");
	}
	size_t instructionAddress = Local<Number>::Cast(info[0])->Value();
	WriteWorker* syncWriter = ew->syncWriter;
	if (!syncWriter)
		syncWriter = ew->syncWriter = new WriteWorker(ew->env, ew, (uint32_t*)instructionAddress, nullptr, nullptr);
	syncWriter->Write();
	if (syncWriter->interruptionStatus)
		return Nan::ThrowError(mdb_strerror(syncWriter->interruptionStatus));
}
