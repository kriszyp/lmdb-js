declare module 'lmdb-store' {
	export function open(path: string, options: RootDatabaseOptions): RootDatabase
	export function open(options: RootDatabaseOptionsWithPath): RootDatabase

	}
	class Database extends NodeJS.EventEmitter {
		get(id: Key): any
		put(id: Key, value: any): Promise<boolean>
		put(id: Key, value: any, version: number, ifVersion?: number): Promise<boolean>
		remove(id: Key): Promise<boolean>
		remove(id: Key, ifVersion: number): Promise<boolean>
		putSync(id: Key, value: any): void
		putSync(id: Key, value: any, version: number): void
		removeSync(id: Key): void
		getRange(options: RangeOptions): ArrayLikeIterable<{ key: Key, value: any, version: number }>
		transaction<T>(action: () => T, abort?: boolean): T
		ifVersion(id: Key, ifVersion: number, action: () => any): Promise<boolean>
		ifNoExists(id: Key, action: () => any): Promise<boolean>
	}
	class RootDatabase extends Database {
		openDB(dbName: string, dbOptions: DatabaseOptions): Database
	}
	type Key = string | symbol | number | boolean | Buffer
	interface DatabaseOptions {
		name?: string
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
		includeValues?: boolean
		includeVersions?: boolean
	}
	class ArrayLikeIterable<T> implements Iterable<T> {
		map<U>(callback: (entry: T) => U): ArrayLikeIterable<U>
		filter(callback: (entry: T) => any): ArrayLikeIterable<T>
		[Symbol.iterator]() : Iterator<T>
		forEach(callback: (entry: T) => any): void
	}
}