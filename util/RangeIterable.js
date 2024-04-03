export const SKIP = {};
const DONE = {
	value: null,
	done: true,
};
const RETURN_DONE = {
	// we allow this one to be mutated
	value: null,
	done: true,
};
if (!Symbol.asyncIterator) {
	Symbol.asyncIterator = Symbol.for('Symbol.asyncIterator');
}

export class RangeIterable {
	constructor(sourceArray) {
		if (sourceArray) {
			this.iterate = sourceArray[Symbol.iterator].bind(sourceArray);
		}
	}
	map(func) {
		let source = this;
		let iterable = new RangeIterable();
		iterable.iterate = (async) => {
			let iterator = source[async ? Symbol.asyncIterator : Symbol.iterator]();
			if (!async) source.isSync = true;
			let i = 0;
			return {
				next(resolvedResult) {
					try {
						let result;
						do {
							let iteratorResult;
							if (resolvedResult) {
								iteratorResult = resolvedResult;
								resolvedResult = null; // don't go in this branch on next iteration
							} else {
								iteratorResult = iterator.next();
								if (iteratorResult.then) {
									if (!async) {
										this.throw(
											new Error(
												'Can not synchronously iterate with asynchronous values',
											),
										);
									}
									return iteratorResult.then(
										(iteratorResult) => this.next(iteratorResult),
										(error) => {
											this.throw(error);
										},
									);
								}
							}
							if (iteratorResult.done === true) {
								this.done = true;
								if (iterable.onDone) iterable.onDone();
								return iteratorResult;
							}
							result = func.call(source, iteratorResult.value, i++);
							if (result && result.then && async) {
								// if async, wait for promise to resolve before returning iterator result
								return result.then(
									(result) =>
										result === SKIP
											? this.next()
											: {
													value: result,
												},
									(error) => {
										this.throw(error);
									},
								);
							}
						} while (result === SKIP);
						if (result === DONE) {
							return this.return();
						}
						return {
							value: result,
						};
					} catch (error) {
						this.throw(error);
					}
				},
				return(value) {
					if (!this.done) {
						RETURN_DONE.value = value;
						this.done = true;
						if (iterable.onDone) iterable.onDone();
						iterator.return();
					}
					return RETURN_DONE;
				},
				throw(error) {
					this.return();
					throw error;
				},
			};
		};
		return iterable;
	}
	[Symbol.asyncIterator]() {
		return (this.iterator = this.iterate(true));
	}
	[Symbol.iterator]() {
		return (this.iterator = this.iterate());
	}
	filter(func) {
		return this.map((element) => {
			let result = func(element);
			// handle promise
			if (result?.then)
				return result.then((result) => (result ? element : SKIP));
			else return result ? element : SKIP;
		});
	}

	forEach(callback) {
		let iterator = (this.iterator = this.iterate());
		let result;
		while ((result = iterator.next()).done !== true) {
			callback(result.value);
		}
	}
	concat(secondIterable) {
		let concatIterable = new RangeIterable();
		concatIterable.iterate = (async) => {
			let iterator = (this.iterator = this.iterate(async));
			let isFirst = true;
			function iteratorDone(result) {
				if (isFirst) {
					try {
						isFirst = false;
						iterator =
							secondIterable[async ? Symbol.asyncIterator : Symbol.iterator]();
						result = iterator.next();
						if (concatIterable.onDone) {
							if (result.then) {
								if (!async)
									throw new Error(
										'Can not synchronously iterate with asynchronous values',
									);
								result.then(
									(result) => {
										if (result.done()) concatIterable.onDone();
									},
									(error) => {
										this.return();
										throw error;
									},
								);
							} else if (result.done) concatIterable.onDone();
						}
					} catch (error) {
						this.throw(error);
					}
				} else {
					if (concatIterable.onDone) concatIterable.onDone();
				}
				return result;
			}
			return {
				next() {
					try {
						let result = iterator.next();
						if (result.then) {
							if (!async)
								throw new Error(
									'Can synchronously iterate with asynchronous values',
								);
							return result.then((result) => {
								if (result.done) return iteratorDone(result);
								return result;
							});
						}
						if (result.done) return iteratorDone(result);
						return result;
					} catch (error) {
						this.return();
						throw error;
					}
				},
				return() {
					if (!this.done) {
						RETURN_DONE.value = value;
						this.done = true;
						if (concatIterable.onDone) concatIterable.onDone();
						iterator.return();
					}
					return RETURN_DONE;
				},
				throw(error) {
					this.return();
					throw error;
				},
			};
		};
		return concatIterable;
	}

	flatMap(callback) {
		let mappedIterable = new RangeIterable();
		mappedIterable.iterate = (async) => {
			let iterator = (this.iterator = this.iterate(async));
			let isFirst = true;
			let currentSubIterator;
			return {
				next(resolvedResult) {
					try {
						do {
							if (currentSubIterator) {
								let result;
								if (resolvedResult) {
									result = resolvedResult;
									resolvedResult = undefined;
								} else result = currentSubIterator.next();
								if (result.then) {
									if (!async)
										throw new Error(
											'Can not synchronously iterate with asynchronous values',
										);
									return result.then((result) => this.next(result));
								}
								if (!result.done) {
									return result;
								}
							}
							let result = resolvedResult ?? iterator.next();
							if (result.then) {
								if (!async)
									throw new Error(
										'Can not synchronously iterate with asynchronous values',
									);
								currentSubIterator = undefined;
								return result.then((result) => this.next(result));
							}
							if (result.done) {
								if (mappedIterable.onDone) mappedIterable.onDone();
								return result;
							}
							let value = callback(result.value);
							if (value?.then) {
								if (!async)
									throw new Error(
										'Can not synchronously iterate with asynchronous values',
									);
								return value.then((value) => {
									if (Array.isArray(value) || value instanceof RangeIterable) {
										currentSubIterator = value[Symbol.iterator]();
										return this.next();
									} else {
										currentSubIterator = null;
										return { value };
									}
								});
							}
							if (Array.isArray(value) || value instanceof RangeIterable)
								currentSubIterator = value[Symbol.iterator]();
							else {
								currentSubIterator = null;
								return { value };
							}
						} while (true);
					} catch (error) {
						this.return();
						throw error;
					}
				},
				return() {
					if (mappedIterable.onDone) mappedIterable.onDone();
					if (currentSubIterator) currentSubIterator.return();
					return iterator.return();
				},
				throw() {
					if (mappedIterable.onDone) mappedIterable.onDone();
					if (currentSubIterator) currentSubIterator.throw();
					return iterator.throw();
				},
			};
		};
		return mappedIterable;
	}

	slice(start, end) {
		return this.map((element, i) => {
			if (i < start) return SKIP;
			if (i >= end) {
				DONE.value = element;
				return DONE;
			}
			return element;
		});
	}
	next() {
		if (!this.iterator) this.iterator = this.iterate();
		return this.iterator.next();
	}
	toJSON() {
		if (this.asArray && this.asArray.forEach) {
			return this.asArray;
		}
		const error = new Error(
			'Can not serialize async iterables without first calling resolving asArray',
		);
		error.resolution = this.asArray;
		throw error;
		//return Array.from(this)
	}
	get asArray() {
		if (this._asArray) return this._asArray;
		let promise = new Promise((resolve, reject) => {
			let iterator = this.iterate(true);
			let array = [];
			let iterable = this;
			Object.defineProperty(array, 'iterable', { value: iterable });
			function next(result) {
				while (result.done !== true) {
					if (result.then) {
						return result.then(next);
					} else {
						array.push(result.value);
					}
					result = iterator.next();
				}
				resolve((iterable._asArray = array));
			}
			next(iterator.next());
		});
		promise.iterable = this;
		return this._asArray || (this._asArray = promise);
	}
	resolveData() {
		return this.asArray;
	}
	at(index) {
		for (let entry of this) {
			if (index-- === 0) return entry;
		}
	}
}
RangeIterable.prototype.DONE = DONE;
