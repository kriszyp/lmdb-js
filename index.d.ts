import { EventEmitter } from 'events'

declare namespace lmdb {
	export function open<V = any, K extends Key = Key>(path: string, options: RootDatabaseOptions): RootDatabase<V, K>
	export function open<V = any, K extends Key = Key>(options: RootDatabaseOptionsWithPath): RootDatabase<V, K>

	class Database<V = any, K extends Key = Key> extends EventEmitter {
		get(id: K): V | undefined
		getEntry(id: K): {
			value: V | undefined
			version?: number
		}
		put(id: K, value: V): Promise<boolean>
		put(id: K, value: V, version: number, ifVersion?: number): Promise<boolean>
		remove(id: K): Promise<boolean>
		remove(id: K, ifVersion: number): Promise<boolean>
		putSync(id: K, value: V): void
		putSync(id: K, value: V, version: number): void
		removeSync(id: K): void
		getRange(options: RangeOptions): ArrayLikeIterable<{ key: K, value: V, version: number }>
		transaction<T>(action: () => T, abort?: boolean): T
		ifVersion(id: K, ifVersion: number, action: () => any): Promise<boolean>
		ifNoExists(id: K, action: () => any): Promise<boolean>
	}
	class RootDatabase<V = any, K extends Key = Key> extends Database<V, K> {
		openDB(options: DatabaseOptions & { name: string }): Database<V, K>
		openDB(dbName: string, dbOptions: DatabaseOptions): Database<V, K>
	}
	type Key = string | symbol | number | boolean | Buffer
	interface DatabaseOptions {
		name?: string
		cache?: boolean
		compression?: boolean | CompressionOptions
		encoding?: 'msgpack' | 'json' | 'string' | 'binary'
		sharedStructuresKey?: Key
		useVersions?: boolean
		keyIsBuffer?: boolean
		keyIsUint32?: boolean
	}
	interface RootDatabaseOptions extends DatabaseOptions {
		/** The maximum number of databases to be able to open (there is some extra overhead if this is set very high).*/
		maxDbs?: number
		commitDelay?: number
		immediateBatchThreshold?: number
		syncBatchThreshold?: number

		/** This provides a small performance boost (when not using useWritemap) for writes, by skipping zero'ing out malloc'ed data, but can leave application data in unused portions of the database. This is recommended unless there are concerns of database files being accessible. */
		noMemInit?: boolean
		/** Use writemaps, this improves performance by reducing malloc calls, but it is possible for a stray pointer to corrupt data. */
		useWritemap?: boolean
		noSubdir?: boolean
		noSync?: boolean
		noMetaSync?: boolean
		readOnly?: boolean
		mapAsync?: boolean
		maxReaders?: number
	}
	interface RootDatabaseOptionsWithPath extends RootDatabaseOptions {
		path: string
	}
	interface CompressionOptions {
		threshold?: number
		dictionary?: Buffer
	}
	interface RangeOptions {
		start?: Key
		end?: Key
		reverse?: boolean
		values?: boolean
		versions?: boolean
		limit?: number
	}
	class ArrayLikeIterable<T> implements Iterable<T> {
		map<U>(callback: (entry: T) => U): ArrayLikeIterable<U>
		filter(callback: (entry: T) => any): ArrayLikeIterable<T>
		[Symbol.iterator]() : Iterator<T>
		forEach(callback: (entry: T) => any): void
		asArray: T[]
	}
	export function getLastVersion(): number
	export function compareKey(a: Key, b: Key): number
}
export = lmdb
