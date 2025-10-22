# Suricata Eve Redis Output Plugin for Suricata 8.0.x

This plugin provides a Suricata Eve output for Redis. It also serves as an
example of how an output plugin that writes to a possibly slow resource like the
network can operate without blocking Suricata.

This plugin can replace the built-in Redis output, but a performance comparison
has not been done.

## Building

```
git clone https://github.com/jasonish/suricata-redis-output
cd suricata-redis-output
cargo build --release
```

## Installing

As there is no standard way (yet) to install Suricata plugins we'll install the
plugin to `/usr/local/lib/suricata/plugins`.

```
mkdir -p /usr/local/lib/suricata/plugins
cp target/release/libredis_output.so /usr/local/lib/suricata/plugins/
```

Add a section to your `suricata.yaml` that looks like:

```
plugins:
  - /usr/local/lib/suricata/plugins/libredis_output.so
```

Then set the `filetype` in your `eve` configuration section to
`eve-redis-plugin`.

## Configuration

This Redis output is compatible with the existing configuration in
`suricata.yaml`.
