# safestream-redactor-native

The optional compiled (Rust) detection core for
[safestream-redactor](https://pypi.org/project/safestream-redactor/). You do not
import this package directly, and it is not published to PyPI. Build and install
it from source (needs a [Rust toolchain](https://rustup.rs)):

```bash
pip install 'git+https://github.com/MounishSenisetty/SafeStream-Redactor#subdirectory=native'
```

and select it:

```bash
safestream redact huge.log -o clean.log --backend native
```

```python
from safestream_redactor import Redactor

Redactor(backend="native").redact("key AKIAIOSFODNN7EXAMPLE")
```

Its output is byte-identical to the pure-Python detection tiers, which CI checks
on every supported CPython before each release. On the project's evaluation corpora
it is 3-12x faster. The two packages are released together with the same version,
and the extra pins that version exactly.

Prebuilt wheels (one abi3 wheel per platform, CPython 3.10 and newer) are published
for Linux (x86_64 and aarch64, glibc and musl), macOS (Intel and Apple Silicon) and
Windows (x64). Elsewhere, pip builds the source distribution, which needs a Rust
toolchain.

Documentation: https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/NATIVE_CORE.md

License: MIT
