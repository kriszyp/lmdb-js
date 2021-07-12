exports.levelup = function(store) {
	return Object.assign(Object.create(store), {
		supports: {
			lotsOfGreatStuff: true
		},
		get(key, options, callback) {
			let result = store.get(key)
			if (typeof options == 'function')
				callback = options
			if (callback) {
				if (result === undefined)
					callback(new NotFoundError())
				else
					callback(null, result)
			} else {
				if (result === undefined)
					return Promise.reject(new NotFoundError())
				else
					return Promise.resolve(result)
			}
		},
		put(key, value, options, callback) {
			let result = store.put(key, value, typeof options == 'object' ? options : undefined)
			if (typeof options == 'function')
				callback = options
			if (callback)
				result.then(result => callback(null, result), error => callback(error))
			return result
		},
		del(key, options, callback) {

		}
	})

}
class NotFoundError extends Error {
	constructor(message) {
		super(message)
		this.type = 'NotFoundError'
		this.notFound = true
	}
}