{
  "variables": {
      "os_linux_compiler%": "gcc",
      "use_vl32%": "false",
  },
  "targets": [
    {
      "target_name": "lmdb-store",
      "win_delay_load_hook": "false",
      "sources": [
        "dependencies/lmdb/libraries/liblmdb/mdb.c",
        "dependencies/lmdb/libraries/liblmdb/midl.c",
        "dependencies/lz4/lib/lz4.h",
        "dependencies/lz4/lib/lz4.c",
        "src/node-lmdb.cpp",
        "src/env.cpp",
        "src/compression.cpp",
        "src/ordered-binary.cpp",
        "src/misc.cpp",
        "src/txn.cpp",
        "src/dbi.cpp",
        "src/cursor.cpp"
      ],
      "defines": ["MDB_FIXEDSIZE", "MDB_VL32"],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
        "dependencies/lmdb/libraries/liblmdb",
        "dependencies/lz4/lib"
      ],
      "conditions": [
        ["OS=='linux'", {
          "variables": {
            "gcc_version" : "<!(<(os_linux_compiler) -dumpversion | cut -d '.' -f 1)",
          },
          "conditions": [
            ["gcc_version>=7", {
              "cflags": [
                "-Wimplicit-fallthrough=2",
              ],
            }],
          ],
          "ldflags": [
            "-fPIC",
            "-fvisibility=hidden"
          ],
          "cflags": [
            "-fPIC",
            "-fvisibility=hidden",
            "-O3"
          ],
          "cflags_cc": [
            "-fPIC",
            "-fvisibility=hidden",
            "-fvisibility-inlines-hidden",
            "-std=c++0x"
          ]
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "OTHER_CPLUSPLUSFLAGS" : ["-std=c++11"],
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "OTHER_LDFLAGS": ["-std=c++11"],
            "CLANG_CXX_LIBRARY": "libc++"
          }
        }],
        ["OS=='win'", {
            "libraries": ["ntdll.lib"]
        }],
        ["use_vl32=='true'", {
          "conditions": [
            ["target_arch=='ia32'", {
                "defines": ["MDB_VL32"]
              }]
            ]
        }],
      ],
    }
  ]
}
