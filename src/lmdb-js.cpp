#include "lmdb-js.h"

using namespace v8;
using namespace node;

int Logging::initLogging() {
    char* logging = getenv("LMDB_JS_LOGGING");
    if (logging)
        fprintf(stderr, "Start logging for lmdb-js\n");
    return !!logging;
}
int Logging::debugLogging = Logging::initLogging();

NODE_MODULE_INIT(/* exports, module, context */) {
    if (Logging::debugLogging)
        fprintf(stderr, "Start initialization\n");
    // Initializes the module
    // Export Env as constructor for EnvWrap
    EnvWrap::setupExports(exports);

    // Export Cursor as constructor for CursorWrap
    CursorWrap::setupExports(exports);

    // Export misc things
    setupExportMisc(exports);
    if (Logging::debugLogging)
        fprintf(stderr, "Finished initialization\n");
}
#ifndef _WIN32
extern "C" void node_module_register(void* m) {
    //fprintf(stderr, "This is just a dummy function to be called if node isn't there so deno can load this module\n");
}
#endif
/* Start of converting just the init to NAPI:
static napi_value Init(napi_env env, napi_value napi_exports) {
    v8::Local<v8::Object> exports;
    memcpy(static_cast<void*>(&exports), &napi_exports, sizeof(napi_exports));
*/

// This file contains code from the node-lmdb project
// Copyright (c) 2013-2017 Timur Kristóf
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
