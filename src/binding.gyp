{
  "targets": [
    {
      "target_name": "node-lmdb",
      "sources": [ "node-lmdb.cpp", "env.cpp", "misc.cpp" ],
      "conditions": [
          ['OS=="linux"', {
            'ldflags': [
              '-llmdb',
            ],
          }],
        ],

    }
  ]
}
