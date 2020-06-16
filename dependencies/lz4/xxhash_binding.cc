#include <string.h>
#include <stdlib.h>

#include <node.h>
#include <node_buffer.h>
#include <nan.h>

#define XXH_PRIVATE_API
#include "../../deps/lz4/lib/xxhash.h"

using namespace node;
using namespace v8;

//-----------------------------------------------------------------------------
// xxHash
//-----------------------------------------------------------------------------
// {Buffer} input, {Integer} seed (optional)
NAN_METHOD(xxHash) {
  Nan::HandleScope scope;

  if (info.Length() == 0) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!Buffer::HasInstance(info[0])) {
    Nan::ThrowTypeError("Wrong argument: Buffer expected");
    return;
  }

  Local<Object> input = Local<Object>::Cast(info[0]);
  uint32_t seed = 0;
  if (info[1]->IsUint32()) {
    seed = info[1]->Uint32Value(Nan::GetCurrentContext()).FromJust();
  }

  Local<Integer> result = Nan::New<Integer>(XXH32(Buffer::Data(input),
                                                Buffer::Length(input),
                                                seed)
                                         );
  info.GetReturnValue().Set(result);
}

// {Integer} seed
NAN_METHOD(xxHash_init) {
  Nan::HandleScope scope;

  if (info.Length() == 0) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!info[0]->IsUint32()) {
    Nan::ThrowTypeError("Wrong argument: Integer expected");
    return;
  }

  uint32_t seed = info[0]->Uint32Value(Nan::GetCurrentContext()).FromJust();

  XXH32_state_t* state = XXH32_createState();
  XXH32_reset(state, seed);
  Nan::MaybeLocal<Object> handle = Nan::NewBuffer((char *)state, sizeof(XXH32_state_t));

  info.GetReturnValue().Set(handle.ToLocalChecked());
}

// {Buffer} state {Buffer} input {Integer} seed
NAN_METHOD(xxHash_update) {
  Nan::HandleScope scope;

  if (info.Length() != 2) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!Buffer::HasInstance(info[0]) || !Buffer::HasInstance(info[1])) {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }

  int err_code = XXH32_update(
    (XXH32_state_t*) Buffer::Data(info[0]),
    Buffer::Data(info[1]),
    Buffer::Length(info[1])
  );

  info.GetReturnValue().Set(Nan::New<Integer>(err_code));
}

// {Buffer} state
NAN_METHOD(xxHash_digest) {
  Nan::HandleScope scope;

  if (info.Length() != 1) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!Buffer::HasInstance(info[0])) {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }

  Local<Integer> res = Nan::New<Integer>(
    XXH32_digest( (XXH32_state_t*) Buffer::Data(info[0]) )
  );

  info.GetReturnValue().Set(res);
}

NAN_MODULE_INIT(init_xxhash) {
  Nan::Export(target, "xxHash", xxHash);
  Nan::Export(target, "init", xxHash_init);
  Nan::Export(target, "update", xxHash_update);
  Nan::Export(target, "digest", xxHash_digest);
}

NODE_MODULE(xxhash, init_xxhash)
