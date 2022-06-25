## Examples

### Build and Run

```shell
cargo run --example <name-of-the-example>
```

For example,
```shell
cargo run --example bbs_simple
```

To collect logs in file,
```shell
RUST_LOG=trace cargo run --example bbs_simple &> bbs_log.txt
```
