const when = require('./when')
const SKIP = {}
if (!Symbol.asyncIterator) {
	Symbol.asyncIterator = Symbol.for('Symbol.asyncIterator')
}

class ArrayLikeIterable {
	constructor(sourceArray) {
		if (sourceArray) {
			this[Symbol.iterator] = sourceArray[Symbol.iterator].bind(sourceArray)
		}
	}
	map(func) {
		let source = this
		let result = new ArrayLikeIterable()
		result[Symbol.iterator] = (async) => {
			let iterator = source[Symbol.iterator](async)
			return {
				next() {
					let result
					do {
						result = iterator.next()
						if (result.done === true) {
							return result
						}
						result = func(result.value)
					} while(result == SKIP)
					return {
						value: result
					}
				},
				return() {
					return iterator.return()
				},
				throw() {
					return iterator.throw()
				}
			}
		}
		return result
	}
	[Symbol.asyncIterator]() {
		return this[Symbol.iterator](true)
	}
	filter(func) {
		return this.map(element => func(element) ? element : SKIP)
	}
	toJSON() {
		if (this._asArray && this._asArray.forEach) {
			return this._asArray
		}
		throw new Error('Can not serialize async iteratables without first calling resolveJSON')
		//return Array.from(this)
	}
	forEach(callback) {
		let iterator = this[Symbol.iterator]()
		let array = []
		let result
		while ((result = iterator.next()).done !== true) {
			callback(result.value)
		}
	}
	get asArray() {
		if (this._asArray)
			return this._asArray
		let array = []
		this.forEach((value) => array.push(value))
		return this._asArray = array
	}
	resolveData() {
		return this.asArray
	}
}
exports.ArrayLikeIterable = ArrayLikeIterable