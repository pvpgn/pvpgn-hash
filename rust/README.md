Usage example

set pvpgn-hash-rs = "1.0.0" in dependencies.
```toml
[dependencies]
pvpgn-hash-rs = "1.0.0"
```

```rust
let str_result = pvpgn_hash_rs::get_hash_string("12345");
println!("{}", str_result.unwrap());
// print 460e0af6c1828a93fe887cbe103d6ca6ab97a0e4
```