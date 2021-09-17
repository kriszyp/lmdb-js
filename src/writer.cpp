/* write instructions

0-3 flags
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
#include <atomic>
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
	// TODO: Make sure this runs on the JS main thread, or we need to move it
	if (envForTxn->writeWorker == this)
		envForTxn->writeWorker = nullptr;
	uv_mutex_destroy(userCallbackLock);
	uv_cond_destroy(userCallbackCond);
}
void WriteWorker::ContinueWrite() {
	//fprintf(stderr, "continueWrite signal %p\n", this);
	uv_mutex_lock(userCallbackLock);
	uv_cond_signal(userCallbackCond);
	//fprintf(stdout, "continue unlock\n");
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
	compressionPointer = std::atomic_exchange((std::atomic_int_fast64_t*) nextCompressible + 1, (int64_t) 0);
	compression = (Compression*)(size_t) * ((double*)&compressionPointer);
	if (compression) {
		value.mv_data = (void*)((size_t) * (nextCompressible - 1));
		value.mv_size = *(((uint32_t*)nextCompressible) - 3);
		//fprintf(stderr, "compressing %p %p %u\n", compression, value.mv_data, value.mv_size);
		argtokey_callback_t compressedData = compression->compress(&value, nullptr);
		if (compressedData) {
			*(((uint32_t*)nextCompressible) - 3) = value.mv_size;
			*((size_t*)(nextCompressible - 1)) = (size_t)value.mv_data;
			int64_t status = std::atomic_exchange((std::atomic_int_fast64_t *)(nextCompressible - 1), (int64_t)value.mv_data);
			//fprintf(stderr, "compression status\n");
			if (status == 1) {
				uv_mutex_lock(envForTxn->writeWorker->userCallbackLock);
				uv_cond_signal(envForTxn->writeWorker->userCallbackCond);
				uv_mutex_unlock(envForTxn->writeWorker->userCallbackLock);
			}
			//fprintf(stdout, "compressed to %p %u\n", value.mv_data, value.mv_size);
		} else
			fprintf(stdout, "failed to compress\n");
		
	}
/*
#ifdef _WIN32
	nextCompressibleSlot = InterlockedExchange64((int64_t*)nextCompressible, 0xffffffffffffffffll);
#else
	nextCompressibleSlot = std::atomic_exchange(((std::atomic_int_fast64_t*) nextCompressible, 0xffffffffffffffffll);
#endif*/
	return (double*)(size_t) * (nextCompressible + 1);
}


void WriteWorker::Compress() {
	//fprintf(stdout, "compress\n");
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
MDB_txn* WriteWorker::AcquireTxn(bool commitSynchronously, int *flags) {
	fprintf(stdout, "acquire lock %u\n", commitSynchronously);
	// TODO: if the conditionDepth is 0, we could allow the current worker's txn to be continued, committed and restarted
	uv_mutex_lock(userCallbackLock);
	if (commitSynchronously && interruptionStatus == ALLOW_COMMIT) {
		interruptionStatus = INTERRUPT_BATCH;
		uv_cond_signal(userCallbackCond);
		uv_mutex_unlock(userCallbackLock);
		*flags |= TXN_HAS_WORKER_LOCK;
		return nullptr;
	} else {
		if (interruptionStatus == RESTART_WORKER_TXN)
			uv_cond_wait(userCallbackCond, userCallbackLock);
		interruptionStatus = USER_HAS_LOCK;
		if (txn)
			*flags |= TXN_HAS_WORKER_LOCK;
		else {
			uv_mutex_unlock(userCallbackLock);
		}
		return txn;
	}
}

void WriteWorker::UnlockTxn() {
	fprintf(stdout, "release txn %u\n", interruptionStatus);
	if (interruptionStatus == RESTART_WORKER_TXN) {
		interruptionStatus = 0;
		uv_mutex_lock(userCallbackLock);
		uv_cond_signal(userCallbackCond);
		uv_mutex_unlock(userCallbackLock);
	} else if (interruptionStatus == USER_HAS_LOCK) {
		interruptionStatus = 0;
		uv_cond_signal(userCallbackCond);
		uv_mutex_unlock(userCallbackLock);
	}
}
int WriteWorker::WaitForCallbacks(MDB_txn** txn, bool allowCommit) {
waitForCallback:
	int rc;
	//fprintf(stderr, "wait for callback %p\n", this);
	if (!finishedProgress)
		executionProgress->Send(nullptr, 0);
	interruptionStatus = allowCommit ? ALLOW_COMMIT : 0;
	uv_cond_wait(userCallbackCond, userCallbackLock);
	if (interruptionStatus == INTERRUPT_BATCH) { // interrupted by JS code that wants to run a synchronous transaction
		fprintf(stderr, "Performing batch interruption %u\n", allowCommit);
		interruptionStatus = RESTART_WORKER_TXN;
		rc = mdb_txn_commit(*txn);
		if (rc == 0) {
			// wait again until the sync transaction is completed
			fprintf(stderr, "Waiting after interruption\n");
			*txn = nullptr;
			uv_cond_wait(userCallbackCond, userCallbackLock);
			// now restart our transaction
			rc = mdb_txn_begin(env, nullptr, 0, txn);
			fprintf(stderr, "Restarted txn after interruption\n");
			envForTxn->currentBatchTxn = *txn;
			interruptionStatus = 0;
			uv_cond_signal(userCallbackCond);
			goto waitForCallback;
		}
		if (rc != 0) {
			fprintf(stdout, "wfc unlock due to error %u\n", rc);
			return rc;
		}
	}
	//fprintf(stderr, "callback done waiting\n");
	return 0;
}

void WriteWorker::Write() {
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
			uv_mutex_lock(userCallbackLock);
			rc = mdb_txn_begin(env, nullptr, 0, &txn);
			txnId = mdb_txn_id(txn);
			if (rc != 0) {
				return SetErrorMessage(mdb_strerror(rc));
			}
		} else {
			txn = envForTxn->writeTxn->txn;
		}
		int validatedDepth = 0;
		double conditionalVersion, setVersion;
		bool startingTransaction = true;
		do {
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
					if (flags & COMPRESSIBLE) {
						uint32_t highPointer = *(instruction + 1);
						if (highPointer > 0x40000000) { // not compressed yet
/*							Compression* compression;
							// this is the algorithm for always compressing if it is not compressed yet (rather than waiting for the other thread)
#ifdef _WIN32
							compression = (Compression*)InterlockedExchange64((int64_t*)(instruction + 4), 0);
#else
							compression = std::atomic_exchange(instruction + 4, 0);
#endif
							if (compression) {
								CompressOne((double*)(instruction + 2));
							} // else it is already done now */
							CompressOne((double*)(instruction + 2));
							if(*(instruction + 1) > 0x40000000) {
								// compression in progress
								fprintf(stderr, "wait on compression\n");
								int64_t fullPointer = std::atomic_exchange((std::atomic_int_fast64_t*)instruction, (int64_t)1);
								if(fullPointer > 0x4000000000000000ll) {
									fprintf(stderr, "really waiting on compression\n");
									uv_cond_wait(userCallbackCond, userCallbackLock);
								}
							}
						}
						// compressed
						value.mv_data = (void*)(size_t) * ((size_t*)instruction);
						value.mv_size = *(instruction - 1);
						instruction += 6; // skip compression pointers
						compressed = true;
					} else {
						value.mv_data = (void*)(size_t) * ((double*)instruction);
						value.mv_size = *(instruction - 1);
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
			//fprintf(stderr, "instr flags %p %p %u\n", start, flags, conditionDepth);
			if (validated || !(flags & CONDITIONAL)) {
				switch (flags & 0xf) {
				case NO_INSTRUCTION_YET:
					instruction -= 2; // reset back to the previous flag as the current instruction
					int previousFlags;
					// we use memory fencing here to make sure all reads and writes are ordered
					previousFlags = std::atomic_fetch_or((std::atomic_uint_fast32_t*) lastStart, (uint32_t)LOCKED);
					rc = 0;
					//fprintf(stderr, "no instruction yet %p %u\n", start, conditionDepth);
					if (!*start && (!finishedProgress || conditionDepth)) {
						*lastStart = (previousFlags & ~LOCKED) | WAITING_OPERATION;
						//fprintf(stderr, "write thread waiting %p\n", lastStart);
						WaitForCallbacks(&txn, conditionDepth == 0);
					}
					if (*start || conditionDepth) {
						//\\fprintf(stderr, "now there is a value available %p\n", *start);
						// the value changed while we were locking or waiting, clear the flags, we are back to running through instructions
						*lastStart = (previousFlags & 0xf) | FINISHED_OPERATION;
						goto next_inst;
					}
					// still nothing to do, end the transaction
					*lastStart = (previousFlags & 0xf) | FINISHED_OPERATION | TXN_DELIMITER;
					//fprintf(stderr, "calling the txn down %p\n", lastStart);
					goto txn_done;
				case BLOCK_END:
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
					rc = validated ? 0 : MDB_NOTFOUND;
					if (validated)
						validatedDepth++;
					conditionDepth++;
					break;
				case USER_CALLBACK:
					finishedProgress = false;
					progressStatus = 2;
					rc = 0;
					if (flags & USER_CALLBACK_STRICT_ORDER) {
						*start = FINISHED_OPERATION; // mark it as finished so it is processed
						WaitForCallbacks(&txn, conditionDepth == 0);
					}
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
			//fprintf(stderr, "finished flag %p\n", flags);
			*start = flags;
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
			txn = nullptr;
			uv_mutex_unlock(userCallbackLock);
			//fprintf(stderr, "committed %p %u\n", instruction, rc);

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
				previousFlags = std::atomic_fetch_or((std::atomic_uint_fast32_t*) lastStart, (uint32_t) LOCKED | TXN_COMMITTED);
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
//			*instruction |= TXN_DELIMITER;
			progressStatus = 1;
			executionProgress->Send(nullptr, 0);
		}
	} while(moreProcessing);
}

void WriteWorker::HandleProgressCallback(const char* data, size_t count) {
	Nan::HandleScope scope;
	v8::Local<v8::Value> argv[] = {
		Nan::New<Number>(progressStatus)
	};
	finishedProgress = true;
	bool immediateContinue = callback->Call(1, argv, async_resource).ToLocalChecked()->IsTrue();
	if (immediateContinue)
		ContinueWrite();
}

void WriteWorker::HandleOKCallback() {
	Nan::HandleScope scope;
	Local<v8::Value> argv[] = {
		Nan::New<Number>(0)
	};
	finishedProgress = true;
	callback->Call(1, argv, async_resource);
}

NAN_METHOD(EnvWrap::startWriting) {
    EnvWrap *ew = Nan::ObjectWrap::Unwrap<EnvWrap>(info.This());
    if (!ew->env) {
        return Nan::ThrowError("The environment is already closed.");
    }
    size_t instructionAddress = Local<Number>::Cast(info[0])->Value();
	if (instructionAddress == 0) {
		ew->writeWorker->ContinueWrite();
		return;
	}
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
	//fprintf(stderr,"Doing sync write\n");
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
