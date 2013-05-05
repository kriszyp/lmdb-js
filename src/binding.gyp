{
  "targets": [
    {
      "target_name": "node-lmdb",
      "sources": [ "node-lmdb.cpp" ],
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
