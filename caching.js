const { WeakLRUCache } = require('weak-lru-cache')
let getLastVersion
exports.CachingStore = Store => class extends Store {
	constructor(dbName, options) {
		super(dbName, options)
		if (!this.env.cacheCommitter) {
			this.env.cacheCommitter = true
			this.on('aftercommit', ({ operations, results }) => {
				results = results || []
				let activeCache
				for (let i = 0, l = operations.length; i < l; i++) {
					let operation = operations[i]
					if (typeof operation[1] === 'object') {
						if (activeCache) {
							if (results[i] === 0)
								activeCache.get(operation[0]) // this will enter it into the LRFU
							else
								activeCache.delete(operation[0]) // just delete it from the map
						}
					} else if (operation && operation.length === undefined) {
						activeCache = operation.cachingDb && operation.cachingDb.cache
					}
				}
			})
		}
		this.db.cachingDb = this
		this.cache = new WeakLRUCache()
		this.cache.loadValue = (id) => {
			let value = super.get(id)
			if (value !== undefined) {
				let entry = new WeakRef(value)
				if (this.useVersions)
					entry.version = getLastVersion()
				return entry
			}
		}
	}
	get(id, cacheMode) {
		let value = this.cache.getValue(id)
		if (value !== undefined)
			return value
		value = super.get(id)
		if (value !== undefined) {
			if (!cacheMode)
				this.cache.set(id, makeEntry(value, this.useVersions && getLastVersion()), value)
			return value
		}
	}
	getEntry(id, cacheMode) {
		let entry = this.cache.get(id)
		if (entry)
			return entry
		let value = super.get(id)
		if (value !== undefined) {
			entry = makeEntry(value, this.useVersions && getLastVersion())
			if (!cacheMode)
				this.cache.set(id, entry, value)
			return entry
		}
	}
	putEntry(entry, ifVersion) {
		let result = super.put(id, entry.value, entry.version, ifVersion)
		if (result && result.then)
			this.cache.setManually(id, entry) // set manually so we can keep it pinned in memory until it is committed
		else // sync operation, immediately add to cache
			this.cache.set(id, entry)
	}
	put(id, value, version, ifVersion) {
		// if (this.cache.get(id)) // if there is a cache entry, remove it from scheduledEntries and 
		let entry = makeEntry(value, version)
		let result = super.put(id, value, version, ifVersion)
		if (result && result.then)
			this.cache.setManually(id, entry) // set manually so we can keep it pinned in memory until it is committed
		else // sync operation, immediately add to cache
			this.cache.set(id, entry)
		return result
	}
	putSync(id, value, version, ifVersion) {
		this.cache.set(id, makeEntry(value, version))
		return super.putSync(id, value, version, ifVersion)
	}
	remove(id, ifVersion) {
		this.cache.delete(id)
		return super.remove(id, ifVersion)
	}
	removeSync(id, ifVersion) {
		this.cache.delete(id)
		return super.removeSync(id, ifVersion)
	}
}
exports.setGetLastVersion = (get) => {
	getLastVersion = get
}
function makeEntry(value, version) {
	let entry
	if (value && typeof value === 'object') {
		entry = new WeakRef(value)
		entry.value = value
	} else
		entry = { value }
	if (typeof version === 'number')
		entry.version = version
	return entry
}
