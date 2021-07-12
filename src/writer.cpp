/* write instructions

0-3 flags
	0 - put with pointer  - 16 + key + 8? + 8? + 8
	8 - put inline

	1 - del - 16 + key + 8?
	2 - del with value
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
const int PUT = 0;
const int DEL = 1;
const int DEL_VALUE = 2;
const int START_BLOCK = 3;
const int POINTER_NEXT = 15;
const int USER_CALLBACK = 4;
const int DROP = 5;
const int BLOCK_END = 11;
const int HAS_VALUE = 2;
const int NEEDS_VALIDATION = 8;
const int CONDITIONAL_VERSION = 0x100;
const int SET_VERSION = 0x200;
const int COMPRESSIBLE = 0x400;
const int DELETE_DATABASE = 0x800;
const int IF_NO_EXISTS = MDB_NOOVERWRITE; //0x10;


WriteWorkerBase::WriteWorkerBase(Nan::Callback *callback, EnvWrap* envForTxn)	: Nan::AsyncProgressWorker(callback, "lmdb:batch"),
		envForTxn(envForTxn) {
	currentTxnWrap = nullptr;	
}
WriteWorkerBase::~WriteWorkerBase() {
	uv_mutex_destroy(userCallbackLock);
	uv_cond_destroy(userCallbackCond);	
}
void WriteWorkerBase::ContinueWrite(int rc, bool hasStarted) {
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



class WriteWorker : public WriteWorkerBase {
	public:
	WriteWorker(MDB_env* env, action_t *actions, int actionCount, int putFlags, KeySpace* keySpace, EnvWrap* envForTxn, uint8_t* results, Nan::Callback *callback)
		: WriteWorkerBase(callback, envForTxn),
		env(env),
		actionCount(actionCount),
		results(results),
		instructions(instructions) {
		interruptionStatus = 0;

	}

	~WriteWorker() {
		delete[] actions;
		delete keySpace;
	}

	void Execute(const ExecutionProgress& executionProgress) {
		MDB_txn *txn;
		// we do compression in this thread to offload from main thread, but do it before transaction to minimize time that the transaction is open
		DbiWrap* dw;
		double* nextCompressible = instructions;
		uint32_t* instruction = (uint32_t*) (nextCompressible + 1);
		MDB_val data;
		while (nextCompressible = ((double*) (size_t) (*nextCompressible))) {
			Compression* compression = (Compression*) (*(nextCompressible + 1));
			data.mv_data = (void*) ((size_t) *(nextCompressible + 2));
			data.mv_size = *((uint32_t*)(nextCompressible + 3));
			void* compressedData = compression->compress(&data, nullptr);
			if (compressedData)
				*(nextCompressible + 2) = compressedData;
		}
		int conditionDepth = 1;
		MDB_val key, data;

		int rc = mdb_txn_begin(env, nullptr, 0, &txn);
		int txnId = mdb_txn_id(txn);
		if (rc != 0) {
			return SetErrorMessage(mdb_strerror(rc));
		}
		if (envForTxn) {
			envForTxn->currentWriteTxn = txn;
			userCallbackLock = new uv_mutex_t;
			userCallbackCond = new uv_cond_t;
			uv_mutex_init(userCallbackLock);
			uv_cond_init(userCallbackCond);
		}
		int validatedDepth = 0;
		lowerMemPriority(envForTxn);
		double conditionalVersion, setVersion;
		do {
			uint32_t flags = *instruction++;
			bool validated = true;
			if ((flags & 0xf) < 4) {
				// a key based instruction, get the key
				MDB_dbi dbi = (MDB_dbi) *instruction++;
				key.mv_size = *instruction++;
				key.mv_data = instruction;
				instruction += (key.mv_size + 8) >> 2;
				if (flags & CONDITIONAL_VERSION) {
					conditionalVersion = *((double*) instruction);
					instruction += 2;
					rc = mdb_get(txn, dbi, &key, &data);
					if (rc)
						validated = false;
					else
						validated = conditionalVersion == *((double*)value.mv_data);
					}
					results[i] = validated ? SUCCESSFUL_OPERATION : FAILED_CONDITION;
				}
				if (flags & SET_VERSION) {
					setVersion = *((double*) instruction);
					instruction += 2;
				}
				if (flags == (IF_NO_EXISTS | START_BLOCK)) {
					rc = mdb_get(txn, dbi, &key, &data);
					validated = rc == MDB_NOTFOUND;
				}
			}
			if (flags & HAS_VALUE) {
				if (flags & COMPRESSIBLE)
					instruction += 4; // skip compression pointers
				data.mv_data = (void*) (size_t) *((double*)instruction);
				instruction += 2;
				data.mv_size = *instruction++;
			}
			if (validated || !(flags & NEEDS_VALIDATION)) {
				switch (flags & 0xf) {
				case PUT:
					if (flags & SET_VERSION)
						rc = putWithVersion(txn, dbi, &key, &data, flags, setVersion);
					else
						rc = mdb_put(txn, dbi, &key, &data, flags);
					if (needsFree)
						free(data.mv_data);
					break;
				case DEL:
					rc = mdb_del(txn, dbi, &key, nullptr);
					break;
				case DEL_VALUE:
					rc = mdb_del(txn, dbi, &key, &data);
					if (needsFree)
						free(data.mv_data);
					break;
				case START_BLOCK:
					conditionDepth++;
					break;
				case USER_CALLBACK:
					uv_mutex_lock(userCallbackLock);
					finishedProgress = false;
					executionProgress.Send(reinterpret_cast<const int char*>(&i), sizeof(int));
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
								envForTxn->currentWriteTxn = txn;
								interruptionStatus = 0;
								uv_cond_signal(userCallbackCond);
								goto waitForCallback;
							}
							if (rc != 0) {
								uv_mutex_unlock(userCallbackLock);
								return SetErrorMessage(mdb_strerror(rc));
							}
						} else {
							uv_mutex_unlock(userCallbackLock);
							rc = interruptionStatus;
							goto done;
						}
					}
					uv_mutex_unlock(userCallbackLock);
					results[i++] = SUCCESSFUL_OPERATION;
				case DROP:
					rc = mdb_drop(txn, dbi, (flags & DELETE_DATABASE) ? 1 : 0);
				case POINTER_NEXT:
					instruction++;
					instruction = (uint32_t*) (size_t) *((double*)instruction);
					break;
				case BLOCK_END;
					conditionDepth--;
					if (validatedDepth > conditionDepth)
						validatedDepth--;
					break;
			}
		} while(conditionDepth)

		for (int i = 0; i < actionCount;) {
			action_t* action = &actions[i];
			int actionType = action->actionType;
			if (actionType >= 8) {
				if (actionType == CHANGE_DB) {
					// reset target db
					dw = action->dw;
				} else if (actionType == RESET_CONDITION) {
					// reset last condition
					conditionDepth--;
					if (validatedDepth > conditionDepth)
						validatedDepth--;
				} else/* if (actionType == USER_TRANSACTION_CALLBACK) */{
					uv_mutex_lock(userCallbackLock);
					finishedProgress = false;
					executionProgress.Send(reinterpret_cast<const int char*>(&i), sizeof(int));
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
								envForTxn->currentWriteTxn = txn;
								interruptionStatus = 0;
								uv_cond_signal(userCallbackCond);
								goto waitForCallback;
							}
							if (rc != 0) {
								uv_mutex_unlock(userCallbackLock);
								return SetErrorMessage(mdb_strerror(rc));
							}
						} else {
							uv_mutex_unlock(userCallbackLock);
							rc = interruptionStatus;
							goto done;
						}
					}
					uv_mutex_unlock(userCallbackLock);
				}
				results[i++] = SUCCESSFUL_OPERATION;
				continue;
			}
			bool validated;
			if (validatedDepth < conditionDepth) {
				// we are in an invalidated branch, just need to track depth
				results[i] = FAILED_CONDITION;
				validated = false;
			} else if (actionType & CONDITION) { // has precondition
				MDB_val value;
				// TODO: Use a cursor
				rc = mdb_get(txn, dw->dbi, &action->key, &value);
				if (rc == MDB_BAD_VALSIZE) {
					results[i] = BAD_KEY;
					validated = false;
				} else {
					if (action->ifVersion == NO_EXIST_VERSION) {
						validated = rc;
					}
					else {
						if (rc)
							validated = false;
						else
							validated = action->ifVersion == *((double*)value.mv_data);
					}
					results[i] = validated ? SUCCESSFUL_OPERATION : FAILED_CONDITION;
				}
				rc = 0;
			} else {
				validated = true;
				results[i] = SUCCESSFUL_OPERATION;
			}
			if (actionType & (WRITE_WITH_VALUE | DELETE_OPERATION)) { // has write operation to perform
				if (validated) {
					if (actionType & DELETE_OPERATION) {
						rc = mdb_del(txn, dw->dbi, &action->key, (actionType & WRITE_WITH_VALUE) ? &action->data : nullptr);
						if (rc == MDB_NOTFOUND) {
							rc = 0; // ignore not_found errors
							results[i] = NOT_FOUND;
						}
					} else {
						if (dw->hasVersions)
							rc = putWithVersion(txn, dw->dbi, &action->key, &action->data, putFlags, action->version);
						else
							rc = mdb_put(txn, dw->dbi, &action->key, &action->data, putFlags);
					}
					if (rc != 0) {
						if (rc == MDB_BAD_VALSIZE) {
							results[i] = BAD_KEY;
							rc = 0;
						} else {
							goto done;
						}
					}
				}
				if (action->freeValue) {
					action->freeValue(action->data);
				}
			} else {
				// starting condition branch
				conditionDepth++;
				if (validated)
					validatedDepth++;
			}
			i++;
		}
done:
		if (envForTxn) {
			envForTxn->currentWriteTxn = nullptr;
			if (currentTxnWrap) {
				// if a transaction was wrapped, need to do clean up
				currentTxnWrap->removeFromEnvWrap();
			}
		}
		if (rc)
			mdb_txn_abort(txn);
		else
			rc = mdb_txn_commit(txn);
		if (rc == 0) {
			if (envForTxn->flags & MDB_OVERLAPPINGSYNC) {
				// successfully completed, we can now send a progress event to tell JS that the commit has been completed
				// and that it is welcome to submit the next transaction, however the commit is not synced/flushed yet,
				// so we continue execution to do that
				i = -1; // indicator of completion
				executionProgress.Send(reinterpret_cast<const int char*>(&i), sizeof(int));
				envForTxn->syncTxnId = txnId;
				rc= mdb_env_sync(env, 1);
				// signal a subsequent txn that we are synced
				uv_cond_signal(envForTxn->syncCond);
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
			if ((putFlags & 1) > 0) // sync mode
				return Nan::ThrowError(mdb_strerror(rc));
			else {
				return SetErrorMessage(mdb_strerror(rc));
			}
		}

	}

	void HandleProgressCallback(const int char* data, size_t count) {
		Nan::HandleScope scope;
		if (interruptionStatus != 0) {
			uv_mutex_lock(userCallbackLock);
			if (interruptionStatus != 0)
				uv_cond_wait(userCallbackCond, userCallbackLock);
			// aquire the lock so that we can ensure that if it is restarting the transaction, it finishes doing that
			uv_mutex_unlock(userCallbackLock);
		}
		v8::Local<v8::Value> argv[] = {
			Nan::True()
		};
		envForTxn->currentWriteTxn = currentTxnWrap;
		bool immediateContinue = callback->Call(1, argv, async_resource).ToLocalChecked()->IsTrue();
		if (immediateContinue)
			ContinueWrite(0, true);
	}

	void HandleOKCallback() {
		Nan::HandleScope scope;
		Local<v8::Value> argv[] = {
			Nan::Null(),
		};

		callback->Call(1, argv, async_resource);
	}

	private:
	MDB_env* env;
	int actionCount;
	uint8_t* results;
	MDB_val compressibles;
	int resultIndex = 0;
	uint32_t* instructions
	int putFlags;
	KeySpace* keySpace;
	friend class DbiWrap;
};
