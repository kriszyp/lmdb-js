const { WeakLRUCache } = require('weak-lru-cache')
let getLastVersion
exports.CachingStore = Store => class extends Store {
	constructor(dbName, options) {
		super(dbName, options)
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
	get(id) {
		let value = this.cache.getValue(id)
		if (value !== undefined)
			return value
		value = super.get(id)
		if (value !== undefined) {
			let entry = (value && typeof value === 'object') ? new WeakRef(value) : { value }
			if (this.useVersions)
				entry.version = getLastVersion()
			this.cache.set(id, entry, value)
			return value
		}
	}
	getEntry(id) {
		let entry = this.cache.get(id)
		if (entry)
			return entry
		let value = super.get(id)
		if (value !== undefined) {
			entry = (value && typeof value === 'object') ? new WeakRef(value) : { value }
			if (this.useVersions)
				entry.version = getLastVersion()
			this.cache.set(id, entry, value)
			return entry
		}
	}
	put(id, value, version, ifVersion) {
		if (this.useVersions) {
			let entry = (value && typeof value === 'object') ? new WeakRef(value) : { value }
			entry.version = version
			this.cache.set(id, entry, value)
		} else
			this.cache.setValue(id, value)
		return super.put(id, value, version, ifVersion)
	}
	putSync(id, value, version, ifVersion) {
		this.cache.setValue(id, value)
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