# Build environment for the Windows GNU toolchain.
#
# The Rust toolchain is the GNU one, but rustup's self-contained linker is not
# used: cargo must be pointed at a mingw-w64 toolchain that provides
# gcc/ar/dlltool. Paths must be Windows-style (C:/...) — rustc is a native
# process and cannot resolve /c/... paths.
#
#   . tools/env.sh
#   "$CARGO" test -p kestrel-core
#   npm run app:build               (from the repo root)
#
# Nothing here is hardcoded to one machine: point KESTREL_MINGW at the
# toolchain's bin directory (or put its gcc on PATH first) and the script works.
#
#   KESTREL_MINGW="C:/path/to/mingw64/bin" . tools/env.sh
#
# The PATH entry must carry cargo too: the tauri CLI shells out to
# `cargo metadata`, and a Windows child process only sees Windows-style
# entries.
#
# `.cargo/config.toml` already requests +crt-static for the gnu target; the
# RUSTFLAGS below repeat it because setting RUSTFLAGS replaces the config flags.

if [ -z "${KESTREL_MINGW:-}" ]; then
  if command -v gcc >/dev/null 2>&1; then
    KESTREL_MINGW="$(dirname "$(command -v gcc)")"
    KESTREL_MINGW="$(cygpath -m "$KESTREL_MINGW" 2>/dev/null || echo "$KESTREL_MINGW")"
  else
    echo "KESTREL_MINGW is not set and no gcc is on PATH." >&2
    echo "Point it at a mingw-w64 bin directory: KESTREL_MINGW=C:/.../mingw64/bin . tools/env.sh" >&2
    return 1 2>/dev/null || exit 1
  fi
fi

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
CARGO_WIN="$(cygpath -m "$CARGO_HOME_DIR" 2>/dev/null || echo "$CARGO_HOME_DIR")"

# Windows processes need `;` separators; bash's own lookups are not needed here.
export PATH="$CARGO_WIN/bin;$KESTREL_MINGW;$PATH"
export CC="$KESTREL_MINGW/gcc.exe"
export AR="$KESTREL_MINGW/ar.exe"
export DLLTOOL="$KESTREL_MINGW/dlltool.exe"
export RUSTFLAGS="-Clinker=$KESTREL_MINGW/gcc.exe -C target-feature=+crt-static"
export CARGO="$CARGO_HOME_DIR/bin/cargo.exe"
