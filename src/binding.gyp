{
  "targets": [
    {
      "target_name": "node-lmdb",
      "sources": [ "node-lmdb.cpp", "env.cpp", "misc.cpp", "txn.cpp" ],
      "conditions": [
          ["OS=='linux'", {
            "ldflags": [
              "-llmdb",
              "-O3",
              "-rdynamic"
            ],
            "cflags": [
              "-fPIC",
              "-fvisibility=hidden",
              "-fvisibility-inlines-hidden",
              "-O3"
            ]
          }],
        ],

    }
  ]
}
