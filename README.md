# MTProto-rs

[MTProto](https://core.telegram.org/mtproto) protocol and schema
implementation in Rust.

Intended to provide low-level features to create a robust foundation for
higher-level libraries such as `telegram-rs`.

Supports Rust 1.31 and newer.
Older versions may work, but are not guaranteed to.


## Features

Currently implemented and planned features include:

- [x] Code autogeneration for TL-schema
      (implemented in [`tl_codegen`][tl_codegen_code])
- [x] MTProto binary [de]serialization
      (handled by [`serde_mtproto`][serde_mtproto_repo])
- [ ] Encryption facilities which enforce
      [security guidelines][mtproto_security_guidelines]
- [x] Key exchange
- [ ] Seamless RPC:
    * Schema functions are modeled as structs
    * Sending requests and receiving responses are automatically
      provided by associated methods
- [x] Handling connections and messages

[tl_codegen_code]: https://github.com/Connicpu/mtproto-rs/tree/master/tl_codegen
[serde_mtproto_repo]: https://github.com/hcpl/serde_mtproto
[mtproto_security_guidelines]: https://core.telegram.org/mtproto/security_guidelines


## Examples

There are 2 examples which you can build and run:

### `auth`

Fetches authorization key over TCP and HTTP.
TCP connection supports 3 modes: abridged, intermediate and full (this example uses all three),
while HTTP only has 1 mode.

Based on [tokio](https://tokio.rs).

```sh
$ cargo run --example auth
# For verbose output use
$ RUST_LOG=auth=info cargo run --example auth
# Even more verbose
$ RUST_LOG=auth=debug cargo run --example auth
```

### `dynamic`

Dynamic typing using `TLObject` in action.

```sh
$ cargo run --example dynamic
# For verbose output use
$ RUST_LOG=dynamic=info cargo run --example dynamic
```

You can also look at [tests](./tests/) for more use cases which are automatically tested.


## License

MTProto-rs is licensed under either of

 * Apache License, Version 2.0, ([LICENSE_APACHE](LICENSE_APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE_MIT](LICENSE_MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in MTProto-rs by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
