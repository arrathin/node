{
  "targets": [{
    "target_name": "debugger-agent",
    "type": "<(library)",
    "include_dirs": [
      "src",
      "include",
      "../v8z/include",
      "../uv/include",

      # Private node.js folder and stuff needed to include from it
      "../../src",
      "../cares/include",
    ],
    "direct_dependent_settings": {
      "include_dirs": [
        "include",
      ],
    },
    'conditions': [
      [ 'gcc_version<=44', {
        # GCC versions <= 4.4 do not handle the aliasing in the queue
        # implementation, so disable aliasing on these platforms
        # to avoid subtle bugs
        'cflags': [ '-fno-strict-aliasing' ],
      }],
      ['OS in "os390"', {
          'defines': [
            '_UNIX03_THREADS',
            '_OPEN_SYS_SOCK_IPV6',
            '_XOPEN_SOURCE=500',
          ],
          'cflags': [
            '-q64',
            '-qxplink',
            '-qlonglong',
            '-qconvlit=ISO8859-1'
          ],
          'ldflags': [
            '-q64',
            '-qxplink'
          ],
      }]

    ],
    "sources": [
      "src/agent.cc",
    ],
  }],
}
