import { WeakLRUCache, clearKeptObjects } from './external.js';
import { FAILED_CONDITION } from './write.js';
let getLastVersion;
const mapGet = Map.prototype.get;
export const CachingStore = Store => class extends Store {
	constructor(dbName, options) {
		super(dbName, options);
		if (!this.env.cacheCommitter) {
			this.env.cacheCommitter = true;
			this.on('aftercommit', ({ next, last }) => {
				do {
					let store = next.store;
					if (store) {
						if (next.flag & FAILED_CONDITION)
							next.store.cache.delete(next.key); // just delete it from the map
						else {
							let expirationPriority = next.valueSize >> 10;
							let cache = next.store.cache;
							let entry = mapGet.call(cache, next.key);
							if (entry)
								cache.used(entry, expirationPriority + 4); // this will enter it into the LRFU (with a little lower priority than a read)
						}
					}
				} while (next != last && (next = next.next))
			});
		}
		this.db.cachingDb = this;
		if (options.cache.clearKeptInterval)
			options.cache.clearKeptObjects = clearKeptObjects;
		this.cache = new WeakLRUCache(options.cache);
	}
	get isCaching() {
		return true
	}
	get(id, cacheMode) {
		let value = this.cache.getValue(id);
		if (value !== undefined)
			return value;
		value = super.get(id);
		if (value && typeof value === 'object' && !cacheMode && typeof id !== 'object') {
			let entry = this.cache.setValue(id, value, this.lastSize >> 10);
			if (this.useVersions) {
				entry.version = getLastVersion();
			}
		}
		return value;
	}
	getEntry(id, cacheMode) {
		let entry = this.cache.get(id);
		if (entry)
			return entry;
		let value = super.get(id);
		if (value === undefined)
			return;
		if (value && typeof value === 'object' && !cacheMode && typeof id !== 'object') {
			entry = this.cache.setValue(id, value, this.lastSize >> 10);
		} else {
			entry = { value };
		}
		if (this.useVersions) {
			entry.version = getLastVersion();
		}
		return entry;
	}
	putEntry(id, entry, ifVersion) {
		let result = super.put(id, entry.value, entry.version, ifVersion);
		if (typeof id === 'object')
			return result;
		if (result && result.then)
			this.cache.setManually(id, entry); // set manually so we can keep it pinned in memory until it is committed
		else // sync operation, immediately add to cache
			this.cache.set(id, entry);
	}
	put(id, value, version, ifVersion) {
		let result = super.put(id, value, version, ifVersion);
		if (typeof id !== 'object') {
			if (value && value['\x10binary-data\x02']) {
				// don't cache binary data, since it will be decoded on get
				this.cache.delete(id);
				return result;
			}	
			// sync operation, immediately add to cache, otherwise keep it pinned in memory until it is committed
			let entry = this.cache.setValue(id, value, !result || result.isSync ? 0 : -1);
			if (version !== undefined)
				entry.version = typeof version === 'object' ? version.version : version;
		}
		return result;
	}
	putSync(id, value, version, ifVersion) {
		if (id !== 'object') {
			// sync operation, immediately add to cache, otherwise keep it pinned in memory until it is committed
			if (value && typeof value === 'object') {
				let entry = this.cache.setValue(id, value);
				if (version !== undefined) {
					entry.version = typeof version === 'object' ? version.version : version;
				}
			} else // it is possible that  a value used to exist here
				this.cache.delete(id);
		}
		return super.putSync(id, value, version, ifVersion);
	}
	remove(id, ifVersion) {
		this.cache.delete(id);
		return super.remove(id, ifVersion);
	}
	removeSync(id, ifVersion) {
		this.cache.delete(id);
		return super.removeSync(id, ifVersion);
	}
	clearAsync(callback) {
		this.cache.clear();
		return super.clearAsync(callback);
	}
	clearSync() {
		this.cache.clear();
		super.clearSync();
	}
	childTransaction(execute) {
		throw new Error('Child transactions are not supported in caching stores');
	}
};
export function setGetLastVersion(get) {
	getLastVersion = get;
}
