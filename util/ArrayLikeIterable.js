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
				next(resolvedResult) {
					let result
					do {
						let iteratorResult
						if (resolvedResult) {
							iteratorResult = resolvedResult
							resolvedResult = null // don't go in this branch on next iteration
						} else {
							iteratorResult = iterator.next()
							if (iteratorResult.then) {
								return iteratorResult.then(iteratorResult => this.next(iteratorResult))
							}
						}
						if (iteratorResult.done === true) {
							return iteratorResult
						}
						result = func(iteratorResult.value)
						if (result && result.then) {
							return result.then(result =>
								result == SKIP ?
									this.next() :
									{
										value: result
									})
						}
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
	get asArray() {
		return this._asArray || (this._asArray = new Promise((resolve, reject) => {
			let iterator = this[Symbol.iterator](true)
			let array = []
			let iterable = this
			function next(result) {
				while (result.done !== true) {
					if (result.then) {
						return result.then(next)
					} else {
						array.push(result.value)
					}
					result = iterator.next()
				}
				resolve(iterable._asArray = array)
			}
			next(iterator.next())
		}))
	}
	resolveData() {
		return this.asArray
	}
}
exports.ArrayLikeIterable = ArrayLikeIterable