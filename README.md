# mantis-capture

## Build

This is a build-time-only dependency for compiling the plugin -- it does not
touch or replace the actual running Suricata binary, and it is separate
from Mantis's own `cargo build` (which just bakes in whatever path the
`.so` ends up at, via `SURICATA_CAPTURE_PLUGIN_PATH` in `build.rs`, the
same way it already does for `SURICATA_PATH`).

On the deployment host (match every version to `suricata -V` there --
plugin support is marked experimental, ABI is not guaranteed across
versions):

```bash
apt-get install -y build-essential autoconf automake libtool pkg-config \
  libjansson-dev libpcap-dev libnet1-dev libcap-ng-dev libmagic-dev \
  liblz4-dev libpcre2-dev libyaml-dev zlib1g-dev
cargo install cbindgen

git clone --branch suricata-8.0.5 https://github.com/OISF/suricata.git
cd suricata && ./autogen.sh && ./configure
make -C rust dist/rust-bindings.h   # headers only, not a full build

cd /path/to/Mantis/mantis/suricata-plugin
make SURICATA_SRC=/path/to/suricata

mkdir -p /path/to/Mantis/lib/suricata
cp mantis-capture.so /path/to/Mantis/lib/suricata/mantis-capture.so
```
