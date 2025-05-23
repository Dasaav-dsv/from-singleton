# FROM Singleton
FromSoftware singleton manipulation library.

This library provides a trait `FromSingleton`, which allows types to be associated with `FD4Singleton` and `FD4DerivedSingleton` static instances across the FromSoftware catalogue of games. It uses binary regex patterns and lazy evaluation, with a first time initialization time of 30-40 ms.

The singleton scanner idea is based on work by tremwil and vswarte.

Supported games (with versions tested):
- [x] DS3 1.15.0
- [x] DS3 1.15.2
- [x] Sekiro 1.06
- [x] ER 1.16
- [x] AC6 1.07.1
- [x] DigitalArtwork_MiniSoundtrack

## License
Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
