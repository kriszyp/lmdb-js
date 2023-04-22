"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var npm_lmdb_1 = require("npm:lmdb");
var chai_4_3_4_dts_1 = require("https://cdn.skypack.dev/chai@4.3.4?dts");
var assert = chai_4_3_4_dts_1.default.assert, should = chai_4_3_4_dts_1.default.should;
should();
try {
    Deno.removeSync('test/testdata', { recursive: true });
}
catch (error) {
    if (error.name != 'NotFound')
        throw error;
}
var db = (0, npm_lmdb_1.open)('test/testdata', {
    name: 'deno-db1',
    useVersions: true,
    overlappingSync: true,
    maxReaders: 100,
    compression: {
        threshold: 128,
    },
});
var db2 = db.openDB({
    name: 'deno-db4',
    create: true,
    dupSort: true,
});
var tests = [];
var test = function (name, test) {
    tests.push({ name: name, test: test });
};
test('query of keys', function () {
    return __awaiter(this, void 0, void 0, function () {
        var keys, _i, keys_1, key, returnedKeys, _a, _b, _c, key, value, _d, _e, _f, key, value;
        return __generator(this, function (_g) {
            switch (_g.label) {
                case 0:
                    keys = [
                        Symbol.for('test'),
                        false,
                        true,
                        -33,
                        -1.1,
                        3.3,
                        5,
                        [5, 4],
                        [5, 55],
                        [5, 'words after number'],
                        [6, 'abc'],
                        ['Test', null, 1],
                        ['Test', Symbol.for('test'), 2],
                        ['Test', 'not null', 3],
                        'hello',
                        ['hello', 3],
                        ['hello', 'world'],
                        ['uid', 'I-7l9ySkD-wAOULIjOEnb', 'Rwsu6gqOw8cqdCZG5_YNF'],
                        'z'
                    ];
                    _i = 0, keys_1 = keys;
                    _g.label = 1;
                case 1:
                    if (!(_i < keys_1.length)) return [3 /*break*/, 4];
                    key = keys_1[_i];
                    return [4 /*yield*/, db.put(key, 3)];
                case 2:
                    _g.sent();
                    _g.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4:
                    returnedKeys = [];
                    for (_a = 0, _b = db.getRange({
                        start: Symbol.for('A')
                    }); _a < _b.length; _a++) {
                        _c = _b[_a], key = _c.key, value = _c.value;
                        returnedKeys.push(key);
                        value.should.equal(db.get(key));
                    }
                    keys.should.deep.equal(returnedKeys);
                    returnedKeys = [];
                    for (_d = 0, _e = db.getRange({
                        reverse: true,
                    }); _d < _e.length; _d++) {
                        _f = _e[_d], key = _f.key, value = _f.value;
                        returnedKeys.unshift(key);
                        value.should.equal(db.get(key));
                    }
                    keys.should.deep.equal(returnedKeys);
                    return [2 /*return*/];
            }
        });
    });
});
test('reverse query range', function () {
    return __awaiter(this, void 0, void 0, function () {
        var keys, _i, keys_2, key, _a, _b, _c, key, value;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    keys = [
                        ['Test', 100, 1],
                        ['Test', 10010, 2],
                        ['Test', 10010, 3]
                    ];
                    _i = 0, keys_2 = keys;
                    _d.label = 1;
                case 1:
                    if (!(_i < keys_2.length)) return [3 /*break*/, 4];
                    key = keys_2[_i];
                    return [4 /*yield*/, db.put(key, 3)];
                case 2:
                    _d.sent();
                    _d.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4:
                    for (_a = 0, _b = db.getRange({
                        start: ['Test', null],
                        end: ['Test', null],
                        reverse: true
                    }); _a < _b.length; _a++) {
                        _c = _b[_a], key = _c.key, value = _c.value;
                        throw new Error('Should not return any results');
                    }
                    return [2 /*return*/];
            }
        });
    });
});
test('more reverse query range', function () {
    return __awaiter(this, void 0, void 0, function () {
        var options, returnedKeys;
        return __generator(this, function (_a) {
            db.putSync('0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdtsud6g8YGhPwUK04fRVKhuTywhnx8', 1, 1, null);
            db.putSync('0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdu0mnkm8lS38yIZa4Xte3Q3JUoD84V', 1, 1, null);
            options = {
                start: '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0SdvKaMkMNPoydWV6HxZbFtKeQm5sqz3',
                end: '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/00000000dKZzSn03pte5dWbaYfrZl4hG',
                reverse: true
            };
            returnedKeys = Array.from(db.getKeys(options));
            returnedKeys.should.deep.equal(['0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdu0mnkm8lS38yIZa4Xte3Q3JUoD84V', '0Sdts8FwTqt2Hv5j9KE7ebjsQcFbYDdL/0Sdtsud6g8YGhPwUK04fRVKhuTywhnx8']);
            return [2 /*return*/];
        });
    });
});
test('clear between puts', function () {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    db.put('key0', 'zero');
                    db.clearAsync();
                    return [4 /*yield*/, db.put('key1', 'one')];
                case 1:
                    _a.sent();
                    assert.equal(db.get('key0'), undefined);
                    assert.equal(db.get('hello'), undefined);
                    assert.equal(db.get('key1'), 'one');
                    return [2 /*return*/];
            }
        });
    });
});
test('string', function () {
    return __awaiter(this, void 0, void 0, function () {
        var data, data2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, db.put('key1', 'Hello world!')];
                case 1:
                    _a.sent();
                    data = db.get('key1');
                    data.should.equal('Hello world!');
                    return [4 /*yield*/, db.remove('key1')];
                case 2:
                    _a.sent();
                    data2 = db.get('key1');
                    assert.equal(data2, undefined);
                    return [2 /*return*/];
            }
        });
    });
});
test('string with version', function () {
    return __awaiter(this, void 0, void 0, function () {
        var entry;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, db.put('key1', 'Hello world!', 53252)];
                case 1:
                    _a.sent();
                    entry = db.getEntry('key1');
                    entry.value.should.equal('Hello world!');
                    entry.version.should.equal(53252);
                    return [4 /*yield*/, db.remove('key1', 33)];
                case 2:
                    (_a.sent()).should.equal(false);
                    entry = db.getEntry('key1');
                    entry.value.should.equal('Hello world!');
                    entry.version.should.equal(53252);
                    return [4 /*yield*/, db.remove('key1', 53252)];
                case 3:
                    (_a.sent()).should.equal(true);
                    entry = db.getEntry('key1');
                    assert.equal(entry, undefined);
                    return [2 /*return*/];
            }
        });
    });
});
test('string with version branching', function () {
    return __awaiter(this, void 0, void 0, function () {
        var entry, result;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, db.put('key1', 'Hello world!', 53252)];
                case 1:
                    _a.sent();
                    entry = db.getEntry('key1');
                    entry.value.should.equal('Hello world!');
                    entry.version.should.equal(53252);
                    return [4 /*yield*/, db.ifVersion('key1', 777, function () {
                            db.put('newKey', 'test', 6);
                            db2.put('keyB', 'test', 6);
                        })];
                case 2:
                    (_a.sent()).should.equal(false);
                    assert.equal(db.get('newKey'), undefined);
                    assert.equal(db2.get('keyB'), undefined);
                    return [4 /*yield*/, db.ifVersion('key1', 53252, function () {
                            db.put('newKey', 'test', 6);
                            db2.put('keyB', 'test', 6);
                        })];
                case 3:
                    result = (_a.sent());
                    assert.equal(db.get('newKey'), 'test');
                    assert.equal(db2.get('keyB'), 'test');
                    assert.equal(result, true);
                    return [4 /*yield*/, db.ifNoExists('key1', function () {
                            db.put('newKey', 'changed', 7);
                        })];
                case 4:
                    result = _a.sent();
                    assert.equal(db.get('newKey'), 'test');
                    assert.equal(result, false);
                    return [4 /*yield*/, db.ifNoExists('key-no-exist', function () {
                            db.put('newKey', 'changed', 7);
                        })];
                case 5:
                    result = _a.sent();
                    assert.equal(db.get('newKey'), 'changed');
                    assert.equal(result, true);
                    return [4 /*yield*/, db2.ifVersion('key-no-exist', npm_lmdb_1.IF_EXISTS, function () {
                            db.put('newKey', 'changed again', 7);
                        })];
                case 6:
                    result = _a.sent();
                    assert.equal(db.get('newKey'), 'changed');
                    assert.equal(result, false);
                    return [4 /*yield*/, db2.ifVersion('keyB', npm_lmdb_1.IF_EXISTS, function () {
                            db.put('newKey', 'changed again', 7);
                        })];
                case 7:
                    result = _a.sent();
                    assert.equal(db.get('newKey'), 'changed again');
                    assert.equal(result, true);
                    return [4 /*yield*/, db2.remove('key-no-exists')];
                case 8:
                    result = _a.sent();
                    assert.equal(result, true);
                    return [4 /*yield*/, db2.remove('key-no-exists', npm_lmdb_1.IF_EXISTS)];
                case 9:
                    result = _a.sent();
                    assert.equal(result, false);
                    return [2 /*return*/];
            }
        });
    });
});
test('string with compression and versions', function () {
    return __awaiter(this, void 0, void 0, function () {
        var str, entry, data;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    str = expand('Hello world!');
                    return [4 /*yield*/, db.put('key1', str, 53252)];
                case 1:
                    _a.sent();
                    entry = db.getEntry('key1');
                    entry.value.should.equal(str);
                    entry.version.should.equal(53252);
                    return [4 /*yield*/, db.remove('key1', 33)];
                case 2:
                    (_a.sent()).should.equal(false);
                    data = db.get('key1');
                    data.should.equal(str);
                    return [4 /*yield*/, db.remove('key1', 53252)];
                case 3:
                    (_a.sent()).should.equal(true);
                    data = db.get('key1');
                    assert.equal(data, undefined);
                    return [2 /*return*/];
            }
        });
    });
});
test('repeated compressions', function () {
    return __awaiter(this, void 0, void 0, function () {
        var str, entry;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    str = expand('Hello world!');
                    db.put('key1', str, 53252);
                    db.put('key1', str, 53253);
                    db.put('key1', str, 53254);
                    return [4 /*yield*/, db.put('key1', str, 53255)];
                case 1:
                    _a.sent();
                    entry = db.getEntry('key1');
                    entry.value.should.equal(str);
                    entry.version.should.equal(53255);
                    return [4 /*yield*/, db.remove('key1')];
                case 2:
                    (_a.sent()).should.equal(true);
                    return [2 /*return*/];
            }
        });
    });
});
test('forced compression due to starting with 255', function () {
    return __awaiter(this, void 0, void 0, function () {
        var entry;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, db.put('key1', (0, npm_lmdb_1.asBinary)(new Uint8Array([255])))];
                case 1:
                    _a.sent();
                    entry = db.getBinary('key1');
                    entry.length.should.equal(1);
                    entry[0].should.equal(255);
                    return [4 /*yield*/, db.remove('key1')];
                case 2:
                    (_a.sent()).should.equal(true);
                    return [2 /*return*/];
            }
        });
    });
});
test('store objects', function () {
    return __awaiter(this, void 0, void 0, function () {
        var dataIn, dataOut;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    dataIn = { foo: 3, bar: true };
                    return [4 /*yield*/, db.put('key1', dataIn)];
                case 1:
                    _a.sent();
                    dataOut = db.get('key1');
                    assert.equal(JSON.stringify(dataIn), JSON.stringify(dataOut));
                    db.removeSync('not-there').should.equal(false);
                    return [2 /*return*/];
            }
        });
    });
});
function expand(str) {
    str = '(' + str + ')';
    str = str + str;
    str = str + str;
    str = str + str;
    str = str + str;
    str = str + str;
    return str;
}
var hasErrors;
for (var _i = 0, tests_1 = tests; _i < tests_1.length; _i++) {
    var _a = tests_1[_i], name_1 = _a.name, test_1 = _a.test;
    try {
        await test_1();
        console.log('Passed:', name_1);
    }
    catch (error) {
        hasErrors = true;
        console.error('Failed:', name_1, error);
    }
}
if (hasErrors)
    throw new Error('Unit tests failed');
