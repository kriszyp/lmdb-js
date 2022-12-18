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
#include "lmdb-js.h"
#include <atomic>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#include <thread>
#endif

const double BATCH_TIME_THRESHOLD = 0.0003; // seconds
// flags:
const uint32_t NO_INSTRUCTION_YET = 0;
const int PUT = 15;
const int DEL = 13;
const int DEL_VALUE = 14;
const int START_CONDITION_BLOCK = 4;
//const int START_CONDITION_VALUE_BLOCK = 6;
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
const int CONDITIONAL_VERSION_LESS_THAN = 0x800;
const int CONDITIONAL_ALLOW_NOTFOUND = 0x1000;
const int SET_VERSION = 0x200;
//const int HAS_INLINE_VALUE = 0x400;
const int COMPRESSIBLE = 0x100000;
const int DELETE_DATABASE = 0x400;
const int TXN_HAD_ERROR = 0x40000000;
const int TXN_DELIMITER = 0x8000000;
const int TXN_COMMITTED = 0x10000000;
//const int TXN_FLUSHED = 0x20000000;
const int WAITING_OPERATION = 0x2000000;
const int IF_NO_EXISTS = MDB_NOOVERWRITE; //0x10;
// result codes:
const int FAILED_CONDITION = 0x4000000;
const int FINISHED_OPERATION = 0x1000000;
const double ANY_VERSION = 3.542694326329068e-103; // special marker for any version


WriteWorker::~WriteWorker() {
	// TODO: Make sure this runs on the JS main thread, or we need to move it
	if (envForTxn->writeWorker == this)
		envForTxn->writeWorker = nullptr;
}

WriteWorker::WriteWorker(MDB_env* env, EnvWrap* envForTxn, uint32_t* instructions)
		: envForTxn(envForTxn),
		instructions(instructions),
		env(env) {
	//fprintf(stdout, "nextCompressibleArg %p\n", nextCompressibleArg);
		interruptionStatus = 0;
		resultCode = 0;
		txn = nullptr;
		nextBatch = nullptr;
	}

void WriteWorker::SendUpdate() {
	if (WriteWorker::threadSafeCallsEnabled)
		napi_call_threadsafe_function(progress, nullptr, napi_tsfn_blocking);
}
MDB_txn* WriteWorker::AcquireTxn(int* flags) {
	bool commitSynchronously = *flags & TXN_SYNCHRONOUS_COMMIT;
	
	// TODO: if the conditionDepth is 0, we could allow the current worker's txn to be continued, committed and restarted
	pthread_mutex_lock(envForTxn->writingLock);
	retry:
	if (commitSynchronously && interruptionStatus == WORKER_WAITING) {
		fprintf(stderr, "acquire lock for synchronous commit from waiting worker %p %u\n", txn, interruptionStatus);
		interruptionStatus = INTERRUPT_BATCH;
		pthread_cond_signal(envForTxn->writingCond);
		pthread_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
		if (interruptionStatus == RESTART_WORKER_TXN) {
			*flags |= TXN_FROM_WORKER;
			pthread_mutex_unlock(envForTxn->writingLock);
			return nullptr;
		} else if (interruptionStatus == WORKER_WAITING || interruptionStatus == INTERRUPT_BATCH) {
			interruptionStatus = WORKER_WAITING;
			goto retry;
		} else {
			pthread_mutex_unlock(envForTxn->writingLock);
			return nullptr;
		}
	} else if (commitSynchronously) {
		fprintf(stderr,"intend to interrupt %p\n", this);
		interruptionStatus = INTERRUPT_BATCH;
		pthread_mutex_unlock(envForTxn->writingLock);
		return nullptr;
	} else {
		//if (interruptionStatus == RESTART_WORKER_TXN)
		//	pthread_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
		interruptionStatus = USER_HAS_LOCK;
		*flags |= TXN_FROM_WORKER;
		if (!txn)
			pthread_mutex_unlock(envForTxn->writingLock);

		fprintf(stderr, "acquire possible lock from worker %p %u\n", txn, commitSynchronously);
		return txn;
	}
}

void WriteWorker::UnlockTxn() {
	interruptionStatus = 0;
	pthread_cond_signal(envForTxn->writingCond);
	fprintf(stderr, "unlock txn pthread_mutex_unlock \n");
	pthread_mutex_unlock(envForTxn->writingLock);
}
int WriteWorker::WaitForCallbacks(MDB_txn** txn, bool allowCommit, uint32_t* target) {
	int rc;
	if (!finishedProgress)
		SendUpdate();
	fprintf(stderr, "WaitForCallbacks %u %p\n", interruptionStatus, this);
	if (interruptionStatus != INTERRUPT_BATCH) {
		pthread_cond_signal(envForTxn->writingCond);
		interruptionStatus = WORKER_WAITING;
		uint64_t start;
		if (envForTxn->trackMetrics)
			start = get_time64();
		if (target) {
			uint64_t delay = 1;
			do {
				cond_timedwait(envForTxn->writingCond, envForTxn->writingLock, delay);
				delay = delay << 1ll;
				if ((*target & 0xf) || (allowCommit && finishedProgress)) {
					// we are in position to continue writing or commit, so forward progress can be made without interrupting yet
					if (envForTxn->trackMetrics) {
						envForTxn->timeTxnWaiting += get_time64() - start;
					}
					fprintf(stderr, "Restarted txn wait %u\n", interruptionStatus);
					if (interruptionStatus == WORKER_WAITING)
						interruptionStatus = 0;
					return 0;
				}
			} while (interruptionStatus != INTERRUPT_BATCH);
		} else {
			pthread_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
		}
		if (envForTxn->trackMetrics) {
			envForTxn->timeTxnWaiting += get_time64() - start;
		}
	}
	if (interruptionStatus == INTERRUPT_BATCH) { // interrupted by JS code that wants to run a synchronous transaction
		interruptionStatus = RESTART_WORKER_TXN;
		rc = mdb_txn_commit(*txn);
#ifdef MDB_EMPTY_TXN
		if (rc == MDB_EMPTY_TXN)
			rc = 0;
#endif
		if (rc == 0) {
			// wait again until the sync transaction is completed
			this->txn = *txn = nullptr;
			interruptionStatus = 0;
			pthread_cond_signal(envForTxn->writingCond);
			pthread_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
			// now restart our transaction
			rc = mdb_txn_begin(env, nullptr, 0, txn);
			this->txn = *txn;
			fprintf(stderr, "Restarted txn after interruption\n");
		}
		if (rc != 0) {
			fprintf(stdout, "wfc unlock due to error %u\n", rc);
			return rc;
		}
	} else
		interruptionStatus = 0;
	return 0;
}
int WriteWorker::DoWrites(MDB_txn* txn, EnvWrap* envForTxn, uint32_t* instruction, WriteWorker* worker) {
	MDB_val key, value;
	int rc = 0;
	int conditionDepth = 0;
	int validatedDepth = 0;
	double conditionalVersion, setVersion = 0;
	bool overlappedWord = !!worker;
	uint32_t* start;
    do {
next_inst:	start = instruction++;
		uint32_t flags = *start;
		MDB_dbi dbi = 0;
		//fprintf(stderr, "do %u %u\n", flags, get_time64());
		bool validated = conditionDepth == validatedDepth;
		if (flags & 0xf0c0) {
			fprintf(stderr, "Unknown flag bits %u %p\n", flags, start);
			fprintf(stderr, "flags after message %u\n", *start);
			worker->resultCode = 22;
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
					int64_t status = -1;
					status = std::atomic_exchange((std::atomic<int64_t>*)(instruction + 2), (int64_t)1);
					if (status == 2) {
						//fprintf(stderr, "wait on compression %p\n", instruction);
						//worker->interruptionStatus = WORKER_WAITING;
						do {
							pthread_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
						} while (std::atomic_load((std::atomic<int64_t>*)(instruction + 2)));
						//TODO: fix this update
						//worker->interruptionStatus = 0;
					} else if (status > 2) {
						//fprintf(stderr, "doing the compression ourselves\n");
						((Compression*) (size_t) *((double*)&status))->compressInstruction(nullptr, (double*) (instruction + 2));
					} // else status is 0 and compression is done
					// compressed
					value.mv_data = (void*)(size_t) * ((size_t*)instruction);
					if ((size_t)value.mv_data > 0x1000000000000)
						fprintf(stderr, "compression not completed %p %i\n", value.mv_data, (int) status);
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
				MDB_val conditionalValue;
				rc = mdb_get(txn, dbi, &key, &conditionalValue);
				if (rc) {
				    // not found counts as version 0, so this is acceptable for conditional less than,
				    // otherwise does not validate
					if (rc == MDB_NOTFOUND)
						validated = flags & CONDITIONAL_ALLOW_NOTFOUND;
					else
						worker->resultCode = rc;
				} else if (conditionalVersion != ANY_VERSION) {
					double version;
					memcpy(&version, conditionalValue.mv_data, 8);
					validated = validated && ((flags & CONDITIONAL_VERSION_LESS_THAN) ? version <= conditionalVersion : (version == conditionalVersion));
				}
			}
			if (flags & SET_VERSION) {
				setVersion = *((double*) instruction);
				instruction += 2;
			}
			if ((flags & IF_NO_EXISTS) && (flags & START_CONDITION_BLOCK)) {
				rc = mdb_get(txn, dbi, &key, &value);
				if (!rc)
					validated = false;
				else if (rc == MDB_NOTFOUND)
					validated = true;
				else
					worker->resultCode = rc;
			}
		} else
			instruction++;
		//fprintf(stderr, "instr flags %p %p %u\n", start, flags, conditionDepth);
		if (validated || !(flags & CONDITIONAL)) {
			switch (flags & 0xf) {
			case NO_INSTRUCTION_YET:
				instruction -= 2; // reset back to the previous flag as the current instruction
				rc = 0;
				// in windows InterlockedCompareExchange might be faster
				if (!worker->finishedProgress || conditionDepth) {
					if (std::atomic_compare_exchange_strong((std::atomic<uint32_t>*) start,
							(uint32_t*) &flags,
							(uint32_t)WAITING_OPERATION)) {
						worker->WaitForCallbacks(&txn, conditionDepth == 0, start);
					}
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
				if (conditionDepth < 0) {
					fprintf(stderr, "Negative condition depth");
				}
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
					while (!worker->finishedProgress) {
						worker->WaitForCallbacks(&txn, conditionDepth == 0, nullptr);
					}
				}
				break;
			case DROP_DB:
				rc = mdb_drop(txn, dbi, (flags & DELETE_DATABASE) ? 1 : 0);
				break;
			case POINTER_NEXT:
				instruction = (uint32_t*)(size_t) * ((double*)instruction);
				goto next_inst;
			default:
				fprintf(stderr, "Unknown flags %u %p\n", flags, start);
				fprintf(stderr, "flags after message %u\n", *start);
				worker->resultCode = 22;
				return 22;
			}
			if (rc) {
				if (!(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND)) {
					if (worker) {
						worker->resultCode = rc;
					} else {
						return rc;
					}
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

bool WriteWorker::threadSafeCallsEnabled = false;
void txn_visible(const void* data) {
	auto worker = (WriteWorker*) data;
	do {
		fprintf(stderr,"send visibility update %p\n",worker);
		worker->FinishWrite(0);
		worker->SendUpdate();
	} while ((worker = worker->nextBatch));
}
void WriteWorker::FinishWrite(int rc) {
	if (!txn)
		return;
	fprintf(stderr, "FinishWrite %i\n", rc);
	txn = nullptr;
	*(instructions - 1) = txnId;
	std::atomic_fetch_or((std::atomic<uint32_t>*) instructions, (uint32_t) TXN_COMMITTED);
	pthread_cond_signal(envForTxn->writingCond); // in case there a sync txn waiting for us
	fprintf(stderr, " pthread_mutex_unlock %p \n", envForTxn);
	pthread_mutex_unlock(envForTxn->writingLock);
}

void do_write(napi_env env, void* data) {
	auto worker = (WriteWorker*) data;
	worker->Write(true);
	napi_release_threadsafe_function(worker->progress, napi_tsfn_abort);
}

void start_next_write(WriteWorker* worker) {
	fprintf(stderr, "start_next_write started");
	worker->Write(false);
	fprintf(stderr, "start_next_write ended");
}

const int READER_CHECK_INTERVAL = 600; // ten minutes
void WriteWorker::Write(bool omitFirstCallback) {
	int rc;
	unsigned int envFlags;
	mdb_env_get_flags(env, &envFlags);
	time_t now = time(0);
	if (now - envForTxn->lastReaderCheck > READER_CHECK_INTERVAL) {
		int dead;
		mdb_reader_check(env, &dead);
		envForTxn->lastReaderCheck = now;
	}
	MDB_txn* write_txn;
	#ifndef _WIN32
	int retries = 0;
	retry:
	#endif
	rc = mdb_txn_begin(env, nullptr,
	#ifdef MDB_OVERLAPPINGSYNC
		(envForTxn->jsFlags & MDB_OVERLAPPINGSYNC) ? MDB_NOSYNC :
	#endif
		0, &write_txn);
	#if !defined(_WIN32) && defined(MDB_RPAGE_CACHE)
	if (rc == MDB_LOCK_FAILURE) {
		if (retries++ < 4) {
			sleep(1);
			goto retry;
		}
	}
	#endif
	if (rc != 0) {
		resultCode = rc;
		return;
	}
	auto context = (env_context_t*) mdb_env_get_userctx(env);
	WriteWorker* current_batch = this;
	WriteWorker* enqueued_batch = nullptr;
	WriteWorker* last_batch = nullptr;
	bool finished;
	uint64_t start = get_time64();
	do {
		fprintf(stderr, "(get_time64() - start) / TICKS_PER_SECOND %f ", (double) (get_time64() - start) / TICKS_PER_SECOND);
		if (last_batch && (double) (get_time64() - start) / TICKS_PER_SECOND > BATCH_TIME_THRESHOLD) {
			// current write batch took too long, starting a new thread
			fprintf(stderr, "current write batch took too long, starting a new thread\n");
			enqueued_batch = current_batch;
			last_batch->nextBatch = nullptr;
			break;
		}
		fprintf(stderr, "locking %p %p ", current_batch, current_batch->envForTxn);
		pthread_mutex_lock(current_batch->envForTxn->writingLock);
		fprintf(stderr, "locked %p %u", current_batch, current_batch->interruptionStatus);
		current_batch->finishedProgress = true;
		current_batch->txn = write_txn;
		rc = DoWrites(write_txn, current_batch->envForTxn, current_batch->instructions, current_batch);
		write_txn = current_batch->txn;
		current_batch->progressStatus = 1;
		current_batch->txnId = (uint32_t) mdb_txn_id(write_txn);
		current_batch->interruptionStatus = 0;
		if (rc || resultCode) {
			std::atomic_fetch_or((std::atomic<uint32_t>*) instructions, (uint32_t) TXN_HAD_ERROR);
			if (rc)
				resultCode = rc ? rc : resultCode;
			pthread_cond_signal(current_batch->envForTxn->writingCond); // in case there a sync txn waiting for us
			fprintf(stderr, " pthread_mutex_unlock %p \n", envForTxn);
			pthread_mutex_unlock(current_batch->envForTxn->writingLock);
			return;
		}

		fprintf(stderr, "finished writes %p ", current_batch);
		do {
			WriteWorker* expected_batch = current_batch;
			// try to assign null to indicate we are done. if there is a new/changed worker, it means
			// another thread has added more writes that we need to process (so we will do that)
			finished = std::atomic_compare_exchange_weak((std::atomic<WriteWorker*>*) &context->submittedWorker,
														 (WriteWorker**) &expected_batch,
														 (WriteWorker*)nullptr);
			fprintf(stderr, "finished %u %p next %p ", finished, current_batch, current_batch->nextBatch);
		} while(!finished && !current_batch->nextBatch);
		last_batch = current_batch;
		current_batch = current_batch->nextBatch;
	} while(!finished);
	#ifdef MDB_OVERLAPPINGSYNC
	if (envForTxn->jsFlags & MDB_OVERLAPPINGSYNC) {
		mdb_txn_set_callback(write_txn, txn_visible, this);
	}
	#endif
	if (enqueued_batch) {
		std::thread next_write_thread(start_next_write, enqueued_batch);
		next_write_thread.detach();
	}
	fprintf(stderr, "committing ");
	if (rc || resultCode)
		mdb_txn_abort(write_txn);
	else
		rc = mdb_txn_commit(write_txn);
	fprintf(stderr, "committed %i ",rc);
#ifdef MDB_EMPTY_TXN
	if (rc == MDB_EMPTY_TXN)
		rc = 0;
#endif
	current_batch = this;
	bool first = omitFirstCallback;
	WriteWorker* next_batch;
	do {
		next_batch = current_batch->nextBatch;
		current_batch->FinishWrite(rc);
		if (first)
			first = false; // will be handled by do_write/writes_complete
		else {
			current_batch->progressStatus = 0;
			fprintf(stderr,"send final update %p\n",current_batch);
			current_batch->SendUpdate();
			napi_release_threadsafe_function(current_batch->progress, napi_tsfn_release);
			//delete current_batch;
		}
	} while ((current_batch = next_batch));
	fprintf(stderr, "done\n");
}

void write_progress(napi_env env,
					napi_value js_callback,
					void* context,
					void* data) {
	if (!js_callback)
		return;
	auto worker = (WriteWorker*) context;
	napi_value result;
	napi_value undefined;
	napi_value arg;
	napi_create_int32(env, worker->progressStatus, &arg);
	napi_get_undefined(env, &undefined);
	fprintf(stderr, "write_progress %i %i \n", worker->progressStatus, worker->finishedProgress);
	if (worker->progressStatus <= 1) {
		napi_call_function(env, undefined, js_callback, 1, &arg, &result);
		return;
	}
	if (worker->finishedProgress)
		return;
	auto envForTxn = worker->envForTxn;
	pthread_mutex_lock(envForTxn->writingLock);
	while(!worker->txn) // possible to jump in after an interrupted txn here
		pthread_cond_wait(envForTxn->writingCond, envForTxn->writingLock);
	envForTxn->writeTxn = new TxnTracked(worker->txn, 0);
	worker->finishedProgress = true;
	napi_create_int32(env, worker->progressStatus, &arg);
	napi_call_function(env, undefined, js_callback, 1, &arg, &result);
	bool is_async = false;
	napi_get_value_bool(env, result, &is_async);
	if (!is_async) {
		delete envForTxn->writeTxn;
		envForTxn->writeTxn = nullptr;
		pthread_cond_signal(envForTxn->writingCond);
		fprintf(stderr, "sync pthread_mutex_unlock\n");
		pthread_mutex_unlock(envForTxn->writingLock);
	}
	// TODO: If final callback:
	// delete data;
}

void writes_complete(napi_env env,
					 napi_status status,
					 void* data) {
	auto worker = (WriteWorker*) data;
	worker->finishedProgress = true;
	napi_value result, arg; // we use direct napi call here because node-addon-api interface with throw a fatal error if a worker thread is terminating, and bun doesn't support escapable scopes yet
	napi_create_int32(env, worker->resultCode, &arg);
	napi_value callback;
	napi_get_reference_value(env, worker->callback, &callback);
	napi_call_function(env, callback, callback, 1, &arg, &result);
	napi_delete_reference(env, worker->callback);
	napi_delete_async_work(env, worker->work);
	delete worker;
}

Value EnvWrap::resumeWriting(const Napi::CallbackInfo& info) {
	// if we had async txns, now we resume
	delete writeTxn;
	writeTxn = nullptr;
	pthread_cond_signal(writingCond);
	fprintf(stderr, " unexpected pthread_mutex_unlock b\n");
	pthread_mutex_unlock(writingLock);
	return info.Env().Undefined();
}

Value EnvWrap::startWriting(const Napi::CallbackInfo& info) {
	napi_env n_env = info.Env();
	if (!env) {
		return throwError(info.Env(), "The environment is already closed.");
	}
	hasWrites = true;
	size_t instructionAddress = info[0].As<Number>().Int64Value();
	napi_value resource;
	napi_status status;
	status = napi_create_object(n_env, &resource);
	napi_value resource_name;
	status = napi_create_string_latin1(n_env, "write", NAPI_AUTO_LENGTH, &resource_name);
	auto worker = new WriteWorker(env, this, (uint32_t*) instructionAddress);
	this->writeWorker = worker;

	auto context = (env_context_t*) mdb_env_get_userctx(env);
	napi_create_threadsafe_function(n_env, info[1].As<Function>(), resource, resource_name, 0, 1, nullptr, nullptr,
									worker, write_progress, &worker->progress);

	auto last_submitted_worker = WriteWorker::threadSafeCallsEnabled ?
			std::atomic_exchange((std::atomic<WriteWorker*>*) &context->submittedWorker, worker) :
								 nullptr;
	if (last_submitted_worker) {
		fprintf(stderr, "adding to current write worker\n");
		// attach to current worker, we don't need to submit a separate task
		last_submitted_worker->nextBatch = worker;
	} else {
		fprintf(stderr, "creating new write worker ");
		napi_create_reference(n_env, info[1].As<Function>(), 1, &worker->callback);
		status = napi_create_async_work(n_env, resource, resource_name, do_write, writes_complete, worker,
										&worker->work);
		status = napi_queue_async_work(n_env, worker->work);
	}

	return info.Env().Undefined();
}

NAPI_FUNCTION(EnvWrap::write) {
	ARGS(2)
	GET_INT64_ARG(0);
	EnvWrap* ew = (EnvWrap*) i64;
	if (!ew->env) {
		napi_throw_error(env, nullptr, "The environment is already closed.");
		RETURN_UNDEFINED;
	}
	ew->hasWrites = true;
	
	napi_get_value_int64(env, args[1], &i64);
	uint32_t* instructionAddress = (uint32_t*) i64;
	int rc = 0;
	if (instructionAddress)
		rc = WriteWorker::DoWrites(ew->writeTxn->txn, ew, instructionAddress, nullptr);
	else if (ew->writeWorker) {
		pthread_cond_signal(ew->writingCond);
	}
	if (rc && !(rc == MDB_KEYEXIST || rc == MDB_NOTFOUND)) {
		throwLmdbError(env, rc);
		RETURN_UNDEFINED;
	}
	RETURN_UNDEFINED;
}
