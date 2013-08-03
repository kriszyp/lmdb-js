
// Indexing engine example
// ----------
// The purpose of this example is to show how to implement an indexing engine using node-lmdb.
// It's not intended to be feature-full, just enough to give you an idea how to use the LMDB API.

// Indexing engine (module pattern)
var indexingEngine = (function() {
    var lmdb, env, dbi;
    
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
    
    var destroy = function() {
        dbi.close();
        env.close();
    };
    
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
    
    var addDocuments = function(array) {
        if (!(array instanceof Array)) {
            throw new Error("This function expects an array.");
        }
        
        for (var i = array.length; i--; ) {
            addDocument(array[i]);
        }
    };
    
    var searchForDocuments = function(str) {
        str = str.toLowerCase();
        var txn = env.beginTxn({ readOnly: true });
        var cursor = new lmdb.Cursor(txn, dbi);
        var results = [];
        
        try {
            var shouldContinue = true;
            cursor.goToRange(str);
            
            while (shouldContinue) {
                shouldContinue = cursor.getCurrentNumber(function(key, data) {
                    //console.log(key.length, str.length, key == str);
                    if (key !== str)
                        return false;

                    results.push(data);
                    return true;
                });
                cursor.goToNext();
            }
        }
        catch (err) {
            console.log(err);
            // Error here only means that we've reached the end
        }
        
        cursor.close();
        txn.abort();
        
        return results;
    };
    
    return {
        init: init,
        destroy: destroy,
        addDocument: addDocument,
        addDocuments: addDocuments,
        searchForDocuments: searchForDocuments
    };
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

