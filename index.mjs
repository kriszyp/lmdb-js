import lmdbModule from './index.js'
const { Env, Cursor, Compression, getLastVersion, setLastVersion, open, compareKey, getLastEntrySize, allDbs } = lmdbModule
export { Env, Cursor, Compression, getLastVersion, setLastVersion, open, compareKey, compareKey as compareKeys, getLastEntrySize, allDbs }
