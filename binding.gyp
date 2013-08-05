{
  "targets": [
    {
      "target_name": "node-lmdb",
      "sources": [
        "src/node-lmdb.cpp",
        "src/env.cpp",
        "src/misc.cpp",
        "src/txn.cpp",
        "src/dbi.cpp",
        "src/cursor.cpp"
      ],
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
        ["OS=='mac'", {
          "xcode_settings": {
            "OTHER_CPLUSPLUSFLAGS" : ["-std=c++11","-stdlib=libc++","-mmacosx-version-min=10.7"],
            "OTHER_LDFLAGS": ["-std=c++11"],
          }
        }],
      ],
    }
  ]
}
