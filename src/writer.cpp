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
const int PUT = 10;
const int DEL = 9;
const int DEL_VALUE = 11;
const int START_CONDITION_BLOCK = 5;
const int START_CONDITION_VALUE_BLOCK = 7;
const int START_BLOCK = 1;
const int BLOCK_END = 0;
const int POINTER_NEXT = 2;
const int USER_CALLBACK = 8;
const int DROP_DB = 13;
const int HAS_VALUE = 2;
const int CONDITIONAL = 8;
const int CONDITIONAL_VERSION = 0x100;
const int SET_VERSION = 0x200;
const int HAS_INLINE_VALUE = 0x400;
const int COMPRESSIBLE = 0x10000000;
const int NOT_COMPRESSED = 0x20000000; // was compressible, but didn't get compressed (probably didn't meet threshold)
const int PROCESSING = 0x20000000; // finished attempt to compress
const int COMPRESSED = 0x30000000;
const int DELETE_DATABASE = 0x400;
const int TXN_DELIMITER = 0x80000000;
const int IF_NO_EXISTS = MDB_NOOVERWRITE; //0x10;
// result codes:
const int FAILED_CONDITION = 1;
const int FINISHED_OPERATION = 0x40000000;
const int BAD_KEY = 3;
const int NOT_FOUND = 1;


WriteWorker::~WriteWorker() {
	uv_mutex_destroy(userCallbackLock);
	uv_cond_destroy(userCallbackCond);	
}
void WriteWorker::ContinueWrite(int rc, bool hasStarted) {
	if (hasStarted) {
		finishedProgress = true;
		currentTxnWrap = envForTxn->currentWriteTxn;
	}
	envForTxn->currentWriteTxn = nullptr;
	uv_mutex_lock(userCallbackLock);
	interruptionStatus = rc;
	uv_cond_signal(userCallbackCond);
	uv_mutex_unlock(userCallbackLock);
}

WriteWorker::WriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions, double* nextCompressible, Nan::Callback *callback)
		: Nan::AsyncProgressWorker(callback, "lmdb:write"),
		env(env),
		envForTxn(envForTxn),
		instructions(instructions),
		nextCompressible(nextCompressible) {
		interruptionStatus = 0;
		currentTxnWrap = nullptr;
	}

void WriteWorker::Compress() {
	MDB_val value;
	uint64_t nextCompressibleSlot;
	while (nextCompressible = ((double*) (size_t) (*nextCompressible))) {
		Compression* compression = (Compression*) (size_t) (*(nextCompressible + 1));
		value.mv_data = (void*) ((size_t) *(nextCompressible + 2));
		value.mv_size = *((uint32_t*)(nextCompressible + 3));
		void* compressedData = compression->compress(&value, nullptr);
		if (compressedData)
			*(nextCompressible + 2) = (size_t) compressedData;
		#ifdef _WIN32
		nextCompressibleSlot = InterlockedExchange64((int64_t*) nextCompressible, 0xffffffffffffffffll);
		#else
		nextCompressibleSlot = atomic_fetch_exchange(compressible, 0xffffffffffffffffll);
		#endif
		nextCompressible = (double*) (size_t) *((double*) (&nextCompressibleSlot));
	}
}

void WriteWorker::Execute(const ExecutionProgress& executionProgress) {
	this->executionProgress = (ExecutionProgress*) &executionProgress;
	if (nextCompressible)
		Compress();
	Write();
}
void WriteWorker::Write() {
	MDB_txn *txn;
	MDB_val key, value;
	uint32_t* instruction = instructions;
	int rc, txnId;
	bool moreProcessing = true;
	bool compressed;
	// we do compression in this thread to offload from main thread, but do it before transaction to minimize time that the transaction is open
	do {
		int conditionDepth = 1;
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
			userCallbackLock = new uv_mutex_t;
			userCallbackCond = new uv_cond_t;
			uv_mutex_init(userCallbackLock);
			uv_cond_init(userCallbackCond);
		}
		int validatedDepth = 0;
		double conditionalVersion, setVersion;
		bool startingTransaction = true;
		do {
			uint32_t* start = instruction++;
			uint32_t flags = *start;
			MDB_dbi dbi;
			bool validated = true;
			if ((flags & 0xf) > 6) {
				// a key based instruction, get the key
				dbi = (MDB_dbi) *instruction++;
				key.mv_size = *instruction++;
				key.mv_data = instruction;
				instruction = (uint32_t*) (((size_t) instruction + key.mv_size + 15) & (~7));
				if (flags & HAS_VALUE) {
					value.mv_size = *(instruction - 1);
					if (flags & COMPRESSIBLE) {
						if (*(instruction + 1) > 0x100000) {
							// compressed
							value.mv_data = (void*) ((size_t*)instruction);
							instruction += 6; // skip compression pointers
							compressed = true;
						}
						else if (*(instruction + 3) == 0xffffffff) {
							// compression attempted, but not compressed
							value.mv_data = (void*)(size_t) * ((double*)instruction);
							instruction += 6;
							compressed = false;
						}
						else {
							// not compressed yet, need to break out until compressed
							instruction -= 3;
							goto done;
						}
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
						validated = conditionalVersion == *((double*)value.mv_data);
				}
				if (flags & SET_VERSION) {
					setVersion = *((double*) instruction);
					instruction += 2;
				}
				if (flags == (IF_NO_EXISTS | START_BLOCK)) {
					rc = mdb_get(txn, dbi, &key, &value);
					validated = rc == MDB_NOTFOUND;
				}
			}
			if (validated || !(flags & CONDITIONAL)) {
				switch (flags & 0xf) {
				case BLOCK_END:
					rc = 0;
					conditionDepth--;
					if (validatedDepth > conditionDepth)
						validatedDepth--;
					if (conditionDepth)
						continue;
					else {
						instruction--; // reset back to the previous flag as the current instruction
						goto done;
					}
				case PUT:
					if (flags & SET_VERSION)
						rc = putWithVersion(txn, dbi, &key, &value, flags & (MDB_NOOVERWRITE | MDB_NODUPDATA | MDB_APPEND | MDB_APPENDDUP), setVersion);
					else
						rc = mdb_put(txn, dbi, &key, &value, flags & (MDB_NOOVERWRITE | MDB_NODUPDATA | MDB_APPEND | MDB_APPENDDUP));
					if ((flags & COMPRESSED) && compressed)
						free(value.mv_data);
					fprintf(stderr, "put %u ", key.mv_size);
					break;
				case DEL:
					rc = mdb_del(txn, dbi, &key, nullptr);
					break;
				case DEL_VALUE:
					rc = mdb_del(txn, dbi, &key, &value);
					if ((flags & COMPRESSED) && compressed)
						free(value.mv_data);
					break;
				case START_BLOCK:
					conditionDepth++;
					break;
				case USER_CALLBACK:
					uv_mutex_lock(userCallbackLock);
					finishedProgress = false;
					progressStatus = 2;
					executionProgress->Send(nullptr, 0);
				waitForCallback:
					if (interruptionStatus == 0)
						uv_cond_wait(userCallbackCond, userCallbackLock);
					if (interruptionStatus != 0 && !finishedProgress) {
						if (interruptionStatus == INTERRUPT_BATCH) { // interrupted by JS code that wants to run a synchronous transaction
							rc = mdb_txn_commit(txn);
							if (rc == 0) {
								// wait again until the sync transaction is completed
								uv_cond_wait(userCallbackCond, userCallbackLock);
								// now restart our transaction
								rc = mdb_txn_begin(env, nullptr, 0, &txn);
								envForTxn->currentBatchTxn = txn;
								interruptionStatus = 0;
								uv_cond_signal(userCallbackCond);
								goto waitForCallback;
							}
							if (rc != 0) {
								uv_mutex_unlock(userCallbackLock);
								return SetErrorMessage(mdb_strerror(rc));
							}
						}
						else {
							uv_mutex_unlock(userCallbackLock);
							rc = interruptionStatus;
							goto done;
						}
					}
					uv_mutex_unlock(userCallbackLock);
				case DROP_DB:
					rc = mdb_drop(txn, dbi, (flags & DELETE_DATABASE) ? 1 : 0);
					break;
				case POINTER_NEXT:
					instruction++;
					instruction = (uint32_t*)(size_t) * ((double*)instruction);
					break;
				}
				flags = FINISHED_OPERATION | (rc ? rc == MDB_NOTFOUND ? NOT_FOUND : rc : 0);
			} else
				flags = FINISHED_OPERATION | FAILED_CONDITION;
			*start = flags;
		} while(true);
done:
		if (envForTxn) {
			envForTxn->currentWriteTxn = nullptr;
			if (currentTxnWrap) {
				// if a transaction was wrapped, need to do clean up
				currentTxnWrap->removeFromEnvWrap();
			}
		}
		if (callback) {
			if (rc)
				mdb_txn_abort(txn);
			else
				rc = mdb_txn_commit(txn);
			fprintf(stderr, "committed ");

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
			if (!*instruction) {
				#ifdef _WIN32
				moreProcessing = InterlockedCompareExchange(instruction, TXN_DELIMITER, NO_INSTRUCTION_YET);
				#else
				moreProcessing = atomic_compare_exchange_strong(instruction, &NO_INSTRUCTION_YET, TXN_DELIMITER);
				#endif
			}
		} else { // sync mode
			if (rc)
				return Nan::ThrowError(mdb_strerror(rc));
			else
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
		uv_mutex_lock(userCallbackLock);
		if (interruptionStatus != 0)
			uv_cond_wait(userCallbackCond, userCallbackLock);
		// aquire the lock so that we can ensure that if it is restarting the transaction, it finishes doing that
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
    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(EnvWrap::writeSync) {
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    Local<Context> context = Nan::GetCurrentContext();
    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }
    size_t instructionAddress = Local<Number>::Cast(info[0])->Value();
    WriteWorker* syncWriter = ew->syncWriter;
    if (!syncWriter)
    	syncWriter = ew->syncWriter = new WriteWorker(ew->env, ew, (uint32_t*) instructionAddress, nullptr, nullptr);
    syncWriter->Write();
}
