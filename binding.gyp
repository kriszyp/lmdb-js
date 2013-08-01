{
  "targets": [
    {
      "target_name": "node-lmdb",
      "sources": [ "src/node-lmdb.cpp", "src/env.cpp", "src/misc.cpp", "src/txn.cpp", "src/dbi.cpp" ],
      "conditions": [
          ["OS=='linux'", {
            "ldflags": [
              "-llmdb",
              "-O3",
              "-rdynamic"
            ],
            "cflags": [
              "-fPIC",
              "-fvisibility-inlines-hidden",
              "-O3",
              "-std=c++11"
            ]
          }],
        ],

    }
  ]
}
