/* write instructions

0-3 flags
4-7 dbi
8-11 key-size
12 ... key followed by at least 2 32-bit zeros
4 value-size
8 bytes: value pointer (or value itself)
8 compressor pointer?
8 bytes (optional): conditional version
8 bytes (optional): version
inline value?
*/
#include "node-lmdb.h"
#include <atomic>
// flags:
const uint32_t NO_INSTRUCTION_YET = 0;
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
const int FAILED_CONDITION = 0x200000;
const int FINISHED_OPERATION = 0x10000000;
const int BATCH_DELIMITER = 0x8000000;


WriteWorker::~WriteWorker() {
	// TODO: Make sure this runs on the JS main thread, or we need to move it
	if (envForTxn->writeWorker == this)
		envForTxn->writeWorker = nullptr;
}
void WriteWorker::ContinueWrite() {
	uv_mutex_lock(envForTxn->writingLock);
	//fprintf(stderr, "continueWrite signal %p\n", this);
	uv_cond_signal(envForTxn->writingCond);
	//fprintf(stdout, "continue unlock\n");
	uv_mutex_unlock(envForTxn->writingLock);
}

WriteWorker::WriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions, Nan::Callback *callback)
		: Nan::AsyncProgressWorker(callback, "lmdb:write"),
		envForTxn(envForTxn),
		env(env),
		instructions(instructions) {
	//fprintf(stdout, "nextCompressibleArg %p\n", nextCompressibleArg);
		interruptionStatus = 0;
		currentTxnWrap = nullptr;
		txn = nullptr;
	}

void WriteWorker::Execute(const ExecutionProgress& executionProgress) {
	this->executionProgress = (ExecutionProgress*) &executionProgress;
	Write();
}
MDB_txn* WriteWorker::AcquireTxn(bool commitSynchronously) {
	fprintf(stderr, "acquire lock %p %u\n", this, commitSynchronously);
	// TODO: if the conditionDepth is 0, we could allow the current worker's txn to be continued, committed and restarted
	uv_mutex_lock(envForTxn->writingLock);
	if (commitSynchronously && interruptionStatus == ALLOW_COMMIT) {
		interruptionStatus = INTERRUPT_BATCH;
		uv_cond_signal(envForTxn->writingCond);
		uv_mutex_unlock(envForTxn->writingLock);
		return nullptr;
	} else {
		if (interruptionStatus == RESTART_WORKER_TXN)
			uv_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
		interruptionStatus = USER_HAS_LOCK;
		return txn;
	}
}

void WriteWorker::UnlockTxn() {
	fprintf(stderr, "release txn %u\n", interruptionStatus);
	if (interruptionStatus == RESTART_WORKER_TXN) {
		interruptionStatus = 0;
		uv_mutex_lock(envForTxn->writingLock);
	}
	interruptionStatus = 0;
	uv_cond_signal(envForTxn->writingCond);
	uv_mutex_unlock(envForTxn->writingLock);
}
void WriteWorker::ReportError(char* error) {
	SetErrorMessage(error);
}
int WriteWorker::WaitForCallbacks(MDB_txn** txn, bool allowCommit, uint32_t* target) {
waitForCallback:
	int rc;
	//fprintf(stderr, "wait for callback %p\n", this);
	if (!finishedProgress)
		executionProgress->Send(nullptr, 0);
	interruptionStatus = allowCommit ? ALLOW_COMMIT : 0;
	if (target) {
		int delay = 1;
		do {
			uv_cond_timedwait(envForTxn->writingCond, envForTxn->writingLock, delay);
			delay = delay << 6;
		} while(!(
			(*target & 0xf) ||
			(allowCommit && (interruptionStatus == INTERRUPT_BATCH || finishedProgress))));
	} else
		uv_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
	if (interruptionStatus == INTERRUPT_BATCH) { // interrupted by JS code that wants to run a synchronous transaction
		fprintf(stderr, "Performing batch interruption %u\n", allowCommit);
		interruptionStatus = RESTART_WORKER_TXN;
		rc = mdb_txn_commit(*txn);
		if (rc == 0) {
			// wait again until the sync transaction is completed
			fprintf(stderr, "Waiting after interruption\n");
			*txn = nullptr;
			uv_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
			// now restart our transaction
			rc = mdb_txn_begin(env, nullptr, 0, txn);
			this->txn = *txn;
			fprintf(stderr, "Restarted txn after interruption\n");
			envForTxn->currentBatchTxn = *txn;
			interruptionStatus = 0;
			uv_cond_signal(envForTxn->writingCond);
			goto waitForCallback;
		}
		if (rc != 0) {
			fprintf(stdout, "wfc unlock due to error %u\n", rc);
			return rc;
		}
	}
//	fprintf(stderr, "callback done waiting\n");
	return 0;
}
int DoWrites(MDB_txn* txn, EnvWrap* envForTxn, uint32_t* instruction, WriteWorker* worker) {
	MDB_val key, value;
	int rc;
	int conditionDepth = 0;
	int validatedDepth = 0;
	double conditionalVersion, setVersion;
	bool overlappedWord = !!worker;
	uint32_t* start;
		do {
next_inst:	start = instruction++;
		uint32_t flags = *start;
		MDB_dbi dbi;
		bool validated = conditionDepth == validatedDepth;
		if (flags & 0xf0c0) {
			fprintf(stderr, "Unknown flag bits %p %p\n", flags, start);
			fprintf(stderr, "flags after message %p\n", *start);
			worker->ReportError("Unknown flags\n");
			return 0;
		}
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
						int64_t status = std::atomic_exchange((std::atomic<int64_t>*)(instruction + 2), (int64_t)1);
						if (status == 2) {
							//fprintf(stderr, "wait on compression %p\n", instruction);
							uv_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
						} else if (status > 2) {
							//fprintf(stderr, "doing the compression ourselves\n");
							((Compression*) (size_t) *((double*)&status))->compressInstruction(nullptr, (double*) (instruction + 2));
						} // else status is 0 and compression is done
					}
					// compressed
					value.mv_data = (void*)(size_t) * ((size_t*)instruction);
					if ((size_t)value.mv_data > 0x1000000000000)
						fprintf(stderr, "compressed %p\n", value.mv_data);
					value.mv_size = *(instruction - 1);
					instruction += 4; // skip compression pointers
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
				rc = 0;
				//fprintf(stderr, "no instruction yet %p %u\n", start, conditionDepth);
				// in windows InterlockedCompareExchange might be faster
				if (!worker->finishedProgress || conditionDepth) {
					//fprintf(stderr, "write thread waiting %p\n", lastStart);
					if (std::atomic_compare_exchange_strong((std::atomic<uint32_t>*) start,
							(uint32_t*) &flags,
							(uint32_t)WAITING_OPERATION))
						worker->WaitForCallbacks(&txn, conditionDepth == 0, start);
					goto next_inst;
				} else {
					if (std::atomic_compare_exchange_strong((std::atomic<uint32_t>*) start,
							(uint32_t*) &flags,
							(uint32_t)TXN_DELIMITER)) {
						worker->instructions = start;
						return 0;
					} else
						goto next_inst;						
				}
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
				if (flags & COMPRESSIBLE)
					free(value.mv_data);
				//fprintf(stdout, "put %u \n", key.mv_size);
				break;
			case DEL:
				rc = mdb_del(txn, dbi, &key, nullptr);
				break;
			case DEL_VALUE:
				rc = mdb_del(txn, dbi, &key, &value);
				if (flags & COMPRESSIBLE)
					free(value.mv_data);
				break;
			case START_BLOCK: case START_CONDITION_BLOCK:
				rc = validated ? 0 : MDB_NOTFOUND;
				if (validated)
					validatedDepth++;
				conditionDepth++;
				break;
			case USER_CALLBACK:
				worker->finishedProgress = false;
				worker->progressStatus = 2;
				rc = 0;
				if (flags & USER_CALLBACK_STRICT_ORDER) {
					std::atomic_fetch_or((std::atomic<uint32_t>*) start, (uint32_t) FINISHED_OPERATION); // mark it as finished so it is processed
					worker->WaitForCallbacks(&txn, conditionDepth == 0, nullptr);
				}
				break;
			case DROP_DB:
				rc = mdb_drop(txn, dbi, (flags & DELETE_DATABASE) ? 1 : 0);
				break;
			case POINTER_NEXT:
				instruction = (uint32_t*)(size_t) * ((double*)instruction);
				goto next_inst;
			default:
				fprintf(stderr, "Unknown flags %p %p\n", flags, start);
				fprintf(stderr, "flags after message %p\n", *start);
				worker->ReportError("Unknown flags\n");
				return 0;
			}
			if (rc) {
				if (!(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND)) {
					fprintf(stderr, "Unknown return code %i %p", rc, start);
					fprintf(stderr, "flags after return code %p\n", *start);
				}
				flags = FINISHED_OPERATION | FAILED_CONDITION;
			}
			else
				flags = FINISHED_OPERATION;
		} else
			flags = FINISHED_OPERATION | FAILED_CONDITION;
		//fprintf(stderr, "finished flag %p\n", flags);
		if (overlappedWord) {
			std::atomic_fetch_or((std::atomic<uint32_t>*) start, flags);
			overlappedWord = false;
		} else
			*start |= flags;
	} while(worker); // keep iterating in async/multiple-instruction mode, just one instruction in sync mode
	return rc;
}

void WriteWorker::Write() {
	int rc, txnId;
	finishedProgress = true;
	uv_mutex_lock(envForTxn->writingLock);
	rc = mdb_txn_begin(env, nullptr, 0, &txn);
	txnId = mdb_txn_id(txn);
	if (rc != 0) {
		return SetErrorMessage(mdb_strerror(rc));
	}

	DoWrites(txn, envForTxn, instructions, this);

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
		MDB_txn* committingTxn = txn;
		rc = mdb_txn_commit(txn);
		txn = nullptr;
		uv_mutex_unlock(envForTxn->writingLock);
		unsigned int envFlags;
		mdb_env_get_flags(env, &envFlags);
		if ((envFlags & MDB_OVERLAPPINGSYNC) && rc == 0) {
			//progressStatus = 1;
			//executionProgress->Send(nullptr, 0);
			rc = mdb_txn_sync(committingTxn);
		}

		//fprintf(stderr, "committed %p %u\n", instructions, rc);
/*
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
		}*/
		if (rc) {
			std::atomic_fetch_or((std::atomic<uint32_t>*) instructions, (uint32_t) rc);
			return SetErrorMessage(mdb_strerror(rc));
		} else
			std::atomic_fetch_or((std::atomic<uint32_t>*) instructions, (uint32_t) TXN_COMMITTED);
	} else
		interruptionStatus = rc;
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
    Nan::Callback* callback = new Nan::Callback(Local<v8::Function>::Cast(info[1]));

    WriteWorker* worker = new WriteWorker(ew->env, ew, (uint32_t*) instructionAddress, callback);
	ew->writeWorker = worker;
    Nan::AsyncQueueWorker(worker);
}


#ifdef ENABLE_FAST_API
void EnvWrap::writeFast(Local<Object> receiver_obj, uint64_t instructionAddress, FastApiCallbackOptions& options) {
	EnvWrap* cw = static_cast<EnvWrap*>(
		receiver_obj->GetAlignedPointerFromInternalField(0));
	size_t instructionAddress = Local<Number>::Cast(info[0])->Value();
	int rc = DoWrites(ew->writeTxn->txn, ew, (uint32_t*)instructionAddress, nullptr);
	if (rc && !(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND))
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
	int rc = DoWrites(ew->writeTxn->txn, ew, (uint32_t*)instructionAddress, nullptr);
	if (rc && !(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND))
		return Nan::ThrowError(mdb_strerror(rc));
}
