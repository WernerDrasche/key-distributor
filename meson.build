project('protocol', 'cpp', default_options: ['cpp_std=c++20'])
cpp = meson.get_compiler('cpp')
src = meson.project_source_root()
if host_machine.system() == 'windows'
  clname = 'cl64'
else
  clname = 'cl'
endif
cryptlib = cpp.find_library(clname, dirs: src)
sqlite3 = dependency('sqlite3', fallback: 'sqlite3')
executable('server', 'server.cpp', dependencies: [sqlite3, cryptlib])
executable('client', 'client.cpp', 'base64.cpp', 'der.cpp', dependencies: cryptlib)
