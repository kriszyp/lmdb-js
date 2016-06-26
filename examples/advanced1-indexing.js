
// Indexing engine example
// ----------
//
// The purpose of this example is to show how to implement an indexing engine using node-lmdb.
// It's not intended to be feature-full, just enough to give you an idea how to use the LMDB API.
//
// Limitations of this indexing engine:
// * Doesn't support fields or advanced querying
// * Tokenization is very simple, no stemming or stop words
// * No phrase search, can only search for single words
//
// But hey, it's only ~100 LOC, so we're still cool :)


// Indexing engine (implemented with the module pattern)
var indexingEngine = (function() {
    var lmdb, env, dbi;

    // initializer function, call this before using the index
    var init = function() {
        lmdb = require('./build/Release/node-lmdb');
        env = new lmdb.Env();
        env.open({
            path: "./testdata",
            maxDbs: 10
        });

        dbi = env.openDbi({
           name: "example-advanced-indexing",
           create: true,
           dupSort: true
        });
    };

    // destroy function, call this when you no longer need the index
    var destroy = function() {
        dbi.close();
        env.close();
    };

    // simple tokenizer
    var tokenize = function(document) {
        var tokens = [];
        for (var i in document) {
            if (document.hasOwnProperty(i) && typeof(document[i]) === "string") {
                var stripped = document[i].replace(/[\.!,?\[\]\\]/g, " ");
                var splitted = stripped.split(" ");

                for (var j = splitted.length; j--; ) {
                    if (splitted[j] !== '' && tokens.indexOf(splitted[j]) === -1) {
                        tokens.push(splitted[j].toLowerCase());
                    }
                }
            }
        }
        return tokens;
    };

    // adds a document to the index
    var addDocument = function(document) {
        if (typeof(document.id) !== "number") {
            throw new Error("document must have an id property");
        }

        var tokens = tokenize(document);
        var txn = env.beginTxn();

        for (var i = tokens.length; i--; ) {
            //console.log(tokens[i], document.id);
            txn.putNumber(dbi, tokens[i], document.id);
        }

        txn.commit();
    };

    // adds multiple documents to the index
    var addDocuments = function(array) {
        if (!(array instanceof Array)) {
            throw new Error("This function expects an array.");
        }

        for (var i = array.length; i--; ) {
            addDocument(array[i]);
        }
    };

    // performs a search in the index for the given word
    var searchForDocuments = function(str) {
        str = str.toLowerCase();
        var txn = env.beginTxn({ readOnly: true });
        var cursor = new lmdb.Cursor(txn, dbi);
        var results = [];

        // Go the the first occourence of `str` and iterate from there
        for (var found = cursor.goToRange(str); found; found = cursor.goToNext()) {
            // Stop the loop if the current key is no longer what we're looking for
            if (found !== str)
                break;

            // Get current data item and push it to results
            cursor.getCurrentNumber(function(key, data) {
                results.push(data);
            });
        }

        cursor.close();
        txn.abort();

        return results;
    };

    // The object we return here is the public API of the indexing engine
    return Object.freeze({
        init: init,
        destroy: destroy,
        addDocument: addDocument,
        addDocuments: addDocuments,
        searchForDocuments: searchForDocuments
    });
})();

indexingEngine.init();

var docs = [];
docs.push({
    id: 1,
    title: "Lord of the Rings",
    text: "Great book by J.R.R. Tolkien!"
});
docs.push({
    id: 2,
    title: "A Game of Thrones",
    text: "Fantasy book by George R.R. Martin, which also has a television adaptation."
});
docs.push({
    id: 3,
    title: "Caves of Steel",
    text: "Science fiction by the great writer Isaac Asimov"
});

for (var i = docs.length; i--; ) {
    console.log("document details:", JSON.stringify(docs[i]));
}

indexingEngine.addDocuments(docs);
console.log("successfully added documents to index");

var s;

console.log("search:", s = "Great", indexingEngine.searchForDocuments(s));
console.log("search:", s = "Asimov", indexingEngine.searchForDocuments(s));
console.log("search:", s = "of", indexingEngine.searchForDocuments(s));
console.log("search:", s = "Lord", indexingEngine.searchForDocuments(s));

indexingEngine.destroy();
