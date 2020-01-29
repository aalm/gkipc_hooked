# gkipc_hooked -- WIP..

if you have the necessary tools set up in your PATH,
build should simply be:
  $ make

which does produce the hw.so ipc hook/wrapper.

simple usage goes like:
  LD_PRELOAD="/full/path/to/hw.so" /path/to/ipc sensortype=sc1135

the cmdline arg isn't necessary atm., needs fixing it back into
being customizable, maybe via env, or config-file...
