#!/usr/bin/env bash
#
# scripts/build-pqc-tls-runtime.sh
#
# Builds the QUANSEC post-quantum TLS data plane:
#
#     OpenSSL 3.5.7 LTS   -> runtime/pqc-tls/openssl
#     NGINX 1.27.5        -> runtime/pqc-tls/nginx   (linked against the above)
#
# WHAT THIS DOES NOT TOUCH
# ------------------------
#   /usr/bin/openssl, /usr/lib/.../libssl*, /etc/ssl   system OpenSSL 3.0.13
#   /usr/sbin/nginx, /etc/nginx, /var/log/nginx        system NGINX 1.24.0
#   /etc/systemd, /opt, /usr/local, ldconfig, PATH
#
# Everything is installed under the project runtime directory, owned by you.
# Deleting runtime/ undoes this script completely.
#
# PRIVILEGES
# ----------
#   * Build dependencies: checked first, and only installed if MISSING.
#     On a machine that already has them (this one does), NO sudo runs at all.
#   * --with-capture additionally runs one setcap on /usr/bin/tcpdump so that
#     loopback packet capture works without sudo afterwards. Opt-in only.
#     Reverse with: sudo setcap -r /usr/bin/tcpdump
#
# USAGE
#   bash scripts/build-pqc-tls-runtime.sh                 # build
#   bash scripts/build-pqc-tls-runtime.sh --check         # report only, no changes
#   bash scripts/build-pqc-tls-runtime.sh --with-capture  # + grant tcpdump capability
#   bash scripts/build-pqc-tls-runtime.sh --force         # rebuild from scratch

set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
NGINX_VERSION="${NGINX_VERSION:-1.27.5}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$BACKEND_DIR")"

# Build root.
#
# Deliberately NOT inside the repository on this machine: the checkout path
# contains spaces ("…/Professional /Industry Project/final project/…"), and
# neither OpenSSL's nor NGINX's build system quotes paths in the Makefiles and
# linker flags they generate. A spaced path makes `ld` split -rpath into
# fragments and the build fails at link time.
#
# ~/.quansec/pqc-tls is still an isolated, project-scoped runtime: it is used by
# nothing else, it is outside every system prefix, and deleting it undoes the
# build completely. Override with QUANSEC_TLS_RUNTIME_DIR if your checkout path
# has no spaces and you would rather keep it in-tree.
DEFAULT_RUNTIME="$HOME/.quansec/pqc-tls"
RUNTIME="${QUANSEC_TLS_RUNTIME_DIR:-$DEFAULT_RUNTIME}"

case "$RUNTIME" in
    *[[:space:]]*)
        printf '\n\033[31mFAILED: runtime path contains whitespace:\033[0m\n  %s\n\n' "$RUNTIME" >&2
        cat >&2 <<'EOF'
OpenSSL and NGINX generate Makefiles and linker flags without quoting paths, so
a build root containing spaces fails at link time with errors such as:

    /usr/bin/ld: cannot find /Industry: No such file or directory

Choose a whitespace-free path:

    QUANSEC_TLS_RUNTIME_DIR=$HOME/.quansec/pqc-tls bash scripts/build-pqc-tls-runtime.sh
EOF
        exit 1
        ;;
esac
SRC_DIR="$RUNTIME/src"
OPENSSL_PREFIX="$RUNTIME/openssl"
NGINX_PREFIX="$RUNTIME/nginx"
JOBS="$(nproc 2>/dev/null || echo 2)"

# NGINX needs these; OpenSSL needs perl. Checked, not blindly installed.
REQUIRED_PACKAGES=(build-essential libpcre2-dev zlib1g-dev perl wget ca-certificates)

WITH_CAPTURE=0
CHECK_ONLY=0
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --with-capture) WITH_CAPTURE=1 ;;
        --check)        CHECK_ONLY=1 ;;
        --force)        FORCE=1 ;;
        -h|--help)      sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m%s\033[0m\n' "$*"; }
warn() { printf '    \033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

# ── State report ─────────────────────────────────────────────────────────────
report() {
    say "Current state"
    echo "    Runtime prefix     : $RUNTIME"
    echo "    System OpenSSL     : $(openssl version 2>/dev/null || echo 'not found')  (untouched)"
    echo "    System NGINX       : $(nginx -v 2>&1 | sed 's|nginx version: ||' || echo 'not found')  (untouched)"

    if [[ -x "$OPENSSL_PREFIX/bin/openssl" ]]; then
        echo "    Runtime OpenSSL    : $("$OPENSSL_PREFIX/bin/openssl" version)"
        if "$OPENSSL_PREFIX/bin/openssl" list -tls-groups 2>/dev/null | grep -qi X25519MLKEM768; then
            ok "X25519MLKEM768   : available"
        else
            warn "X25519MLKEM768   : NOT listed"
        fi
    else
        echo "    Runtime OpenSSL    : not built"
    fi

    if [[ -x "$NGINX_PREFIX/sbin/nginx" ]]; then
        echo "    Runtime NGINX      : $("$NGINX_PREFIX/sbin/nginx" -v 2>&1 | sed 's|nginx version: ||')"
        echo "    NGINX linked with  : $("$NGINX_PREFIX/sbin/nginx" -V 2>&1 | grep -o 'built with OpenSSL [^ ]*  *[^ ]*' || echo unknown)"
    else
        echo "    Runtime NGINX      : not built"
    fi

    local caps; caps="$(getcap /usr/bin/tcpdump 2>/dev/null || true)"
    echo "    tcpdump capability : ${caps:-none (packet capture needs sudo)}"
}

if [[ "$CHECK_ONLY" == 1 ]]; then
    report
    exit 0
fi

# ── Dependencies: check first, install only what is missing ──────────────────
say "Checking build dependencies"
MISSING=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        ok "$pkg present"
    else
        warn "$pkg MISSING"
        MISSING+=("$pkg")
    fi
done

if [[ ${#MISSING[@]} -eq 0 ]]; then
    ok "All dependencies satisfied - no package installation, no sudo required."
else
    say "The following packages are missing and require sudo to install"
    echo "    sudo apt-get install -y ${MISSING[*]}"
    read -rp "    Run that now? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || die "Dependencies missing; install them and re-run."
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING[@]}"
fi

# ── Layout ───────────────────────────────────────────────────────────────────
say "Preparing $RUNTIME"
mkdir -p "$SRC_DIR" "$RUNTIME"/{conf,logs,run,tmp,evidence}
ok "created (git-ignored; nothing here is committed)"

# ── Fetch + verify ───────────────────────────────────────────────────────────
fetch() {
    local url="$1" dest="$2"
    if [[ -f "$dest" && "$FORCE" != 1 ]]; then
        ok "$(basename "$dest") already downloaded"
        return
    fi
    wget -q --show-progress -O "$dest.part" "$url" || die "download failed: $url"
    mv "$dest.part" "$dest"
}

say "Downloading sources"
OPENSSL_TAR="$SRC_DIR/openssl-$OPENSSL_VERSION.tar.gz"
NGINX_TAR="$SRC_DIR/nginx-$NGINX_VERSION.tar.gz"

fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" "$OPENSSL_TAR"
fetch "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" "$NGINX_TAR"

say "Verifying integrity"
# OpenSSL publishes a SHA-256 alongside each release: verify against upstream.
if wget -q -O "$SRC_DIR/openssl.sha256" \
    "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz.sha256" 2>/dev/null; then
    expected="$(tr -d ' \n' < "$SRC_DIR/openssl.sha256" | grep -oE '[0-9a-f]{64}')"
    actual="$(sha256sum "$OPENSSL_TAR" | awk '{print $1}')"
    [[ "$expected" == "$actual" ]] || die "OpenSSL checksum mismatch: expected $expected got $actual"
    ok "OpenSSL SHA-256 verified against upstream"
else
    warn "Could not fetch upstream OpenSSL checksum - recording ours only"
fi
# NGINX ships PGP signatures rather than checksum files. We record the hash as
# evidence and state plainly that it was not verified against upstream.
sha256sum "$OPENSSL_TAR" "$NGINX_TAR" > "$RUNTIME/evidence/source-hashes.txt"
warn "NGINX tarball hash recorded, NOT verified against upstream (PGP only)"

# ── OpenSSL ──────────────────────────────────────────────────────────────────
if [[ -x "$OPENSSL_PREFIX/bin/openssl" && "$FORCE" != 1 ]] \
   && "$OPENSSL_PREFIX/bin/openssl" version | grep -q "$OPENSSL_VERSION"; then
    say "OpenSSL $OPENSSL_VERSION already built - skipping"
else
    say "Building OpenSSL $OPENSSL_VERSION (this is the slow part)"
    rm -rf "$SRC_DIR/openssl-$OPENSSL_VERSION"
    tar xf "$OPENSSL_TAR" -C "$SRC_DIR"
    pushd "$SRC_DIR/openssl-$OPENSSL_VERSION" >/dev/null

    # --libdir=lib keeps the path predictable (OpenSSL defaults to lib64 here),
    # which matters because NGINX and the rpath below both hardcode it.
    #
    # The -Wl,-rpath is NOT optional. Without it the freshly built `openssl`
    # binary has no runtime search path, so the dynamic loader finds the system
    # /lib/x86_64-linux-gnu/libssl.so.3 (3.0.13) first and the binary fails with
    # "version OPENSSL_3.5.0 not found". Since we must not touch ldconfig or the
    # system libraries, the rpath is what keeps this install self-contained.
    ./Configure \
        --prefix="$OPENSSL_PREFIX" \
        --openssldir="$OPENSSL_PREFIX/ssl" \
        --libdir=lib \
        shared \
        "-Wl,-rpath,$OPENSSL_PREFIX/lib" \
        > "$RUNTIME/logs/openssl-configure.log" 2>&1 || die "OpenSSL configure failed (see logs/openssl-configure.log)"

    make -j"$JOBS" > "$RUNTIME/logs/openssl-build.log" 2>&1 \
        || die "OpenSSL build failed (see logs/openssl-build.log)"
    # install_sw skips the man pages, which take longer than the build itself.
    make install_sw install_ssldirs >> "$RUNTIME/logs/openssl-build.log" 2>&1 \
        || die "OpenSSL install failed"
    popd >/dev/null
    ok "installed to $OPENSSL_PREFIX"
fi

say "Gate 1a: does the runtime OpenSSL load its OWN libraries?"
if ldd "$OPENSSL_PREFIX/bin/openssl" | grep -E "libssl|libcrypto" | grep -q "$OPENSSL_PREFIX"; then
    ldd "$OPENSSL_PREFIX/bin/openssl" | grep -E "libssl|libcrypto" | sed 's/^/    /'
    ok "resolves libssl/libcrypto from $OPENSSL_PREFIX, not /lib/x86_64-linux-gnu"
else
    ldd "$OPENSSL_PREFIX/bin/openssl" | grep -E "libssl|libcrypto" | sed 's/^/    /' || true
    die "The runtime openssl binary links against the SYSTEM libssl.
       The rpath did not take effect. Re-run with --force."
fi

say "Gate 1b: does the runtime OpenSSL provide the hybrid group?"
"$OPENSSL_PREFIX/bin/openssl" version | sed 's/^/    /'
"$OPENSSL_PREFIX/bin/openssl" version | grep -q "$OPENSSL_VERSION" \
    || die "Runtime openssl reports the wrong version - expected $OPENSSL_VERSION"
if "$OPENSSL_PREFIX/bin/openssl" list -tls-groups | grep -qi X25519MLKEM768; then
    ok "X25519MLKEM768 is available"
    "$OPENSSL_PREFIX/bin/openssl" list -tls-groups | grep -i mlkem | sed 's/^/      /'
else
    die "X25519MLKEM768 not listed by the freshly built OpenSSL - stopping."
fi

# ── NGINX ────────────────────────────────────────────────────────────────────
if [[ -x "$NGINX_PREFIX/sbin/nginx" && "$FORCE" != 1 ]] \
   && "$NGINX_PREFIX/sbin/nginx" -v 2>&1 | grep -q "$NGINX_VERSION" \
   && "$NGINX_PREFIX/sbin/nginx" -V 2>&1 | grep -q "OpenSSL $OPENSSL_VERSION"; then
    say "NGINX $NGINX_VERSION already built against OpenSSL $OPENSSL_VERSION - skipping"
else
    say "Building NGINX $NGINX_VERSION against $OPENSSL_PREFIX"
    rm -rf "$SRC_DIR/nginx-$NGINX_VERSION"
    tar xf "$NGINX_TAR" -C "$SRC_DIR"
    pushd "$SRC_DIR/nginx-$NGINX_VERSION" >/dev/null

    # Dynamic linkage with an rpath, so nginx loads OUR libssl at runtime while
    # the system loader default stays untouched. Every path is inside $RUNTIME
    # so nothing needs root and nothing lands in /usr/local.
    ./configure \
        --prefix="$NGINX_PREFIX" \
        --sbin-path="$NGINX_PREFIX/sbin/nginx" \
        --conf-path="$RUNTIME/conf/nginx.conf" \
        --pid-path="$RUNTIME/run/nginx.pid" \
        --lock-path="$RUNTIME/run/nginx.lock" \
        --error-log-path="$RUNTIME/logs/error.log" \
        --http-log-path="$RUNTIME/logs/access.json.log" \
        --http-client-body-temp-path="$RUNTIME/tmp/client_body" \
        --http-proxy-temp-path="$RUNTIME/tmp/proxy" \
        --http-fastcgi-temp-path="$RUNTIME/tmp/fastcgi" \
        --http-uwsgi-temp-path="$RUNTIME/tmp/uwsgi" \
        --http-scgi-temp-path="$RUNTIME/tmp/scgi" \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-http_stub_status_module \
        --with-cc-opt="-I$OPENSSL_PREFIX/include" \
        --with-ld-opt="-L$OPENSSL_PREFIX/lib -Wl,-rpath,$OPENSSL_PREFIX/lib" \
        > "$RUNTIME/logs/nginx-configure.log" 2>&1 || die "NGINX configure failed (see logs/nginx-configure.log)"

    make -j"$JOBS" > "$RUNTIME/logs/nginx-build.log" 2>&1 \
        || die "NGINX build failed (see logs/nginx-build.log)"
    make install >> "$RUNTIME/logs/nginx-build.log" 2>&1 || die "NGINX install failed"
    popd >/dev/null
    ok "installed to $NGINX_PREFIX"
fi

# ── The gate that matters ────────────────────────────────────────────────────
say "Gate 2: is NGINX actually built against OpenSSL $OPENSSL_VERSION?"
NGINX_V="$("$NGINX_PREFIX/sbin/nginx" -V 2>&1)"
echo "$NGINX_V" | grep -E "^nginx version|^built with" | sed 's/^/    /'

echo "$NGINX_V" | grep -q "nginx/$NGINX_VERSION" \
    || die "NGINX version is not $NGINX_VERSION"
echo "$NGINX_V" | grep -q "built with OpenSSL $OPENSSL_VERSION" \
    || die "NGINX is NOT built with OpenSSL $OPENSSL_VERSION. Refusing to continue -
       a data plane linked against OpenSSL 3.0 cannot enforce X25519MLKEM768."
ok "nginx -V reports OpenSSL $OPENSSL_VERSION"

say "Gate 3: runtime linkage"
if ldd "$NGINX_PREFIX/sbin/nginx" | grep -q "$OPENSSL_PREFIX"; then
    ldd "$NGINX_PREFIX/sbin/nginx" | grep -E "libssl|libcrypto" | sed 's/^/    /'
    ok "resolves libssl/libcrypto from $OPENSSL_PREFIX, not the system"
else
    ldd "$NGINX_PREFIX/sbin/nginx" | grep -E "libssl|libcrypto" | sed 's/^/    /' || true
    die "NGINX does not resolve OpenSSL from $OPENSSL_PREFIX at runtime."
fi

echo "$NGINX_V" > "$RUNTIME/evidence/nginx-V.txt"
ldd "$NGINX_PREFIX/sbin/nginx" > "$RUNTIME/evidence/nginx-ldd.txt"
"$OPENSSL_PREFIX/bin/openssl" list -tls-groups > "$RUNTIME/evidence/openssl-tls-groups.txt"
ok "evidence written to $RUNTIME/evidence/"

# ── Optional: packet capture capability ──────────────────────────────────────
if [[ "$WITH_CAPTURE" == 1 ]]; then
    say "Granting packet-capture capability to /usr/bin/tcpdump"
    echo "    This is a PERSISTENT change to a system binary."
    echo "    Command : sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump"
    echo "    Undo    : sudo setcap -r /usr/bin/tcpdump"
    read -rp "    Proceed? [y/N] " reply
    if [[ "$reply" =~ ^[Yy]$ ]]; then
        sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
        ok "granted: $(getcap /usr/bin/tcpdump)"
    else
        warn "skipped - packet capture will need sudo per run"
    fi
fi

report
say "Build complete"
cat <<EOF
    Next:
      bash scripts/start-pqc-tls.sh      # NGINX PQ TLS data plane on 127.0.0.1:8443
      bash scripts/test-pqc-tls.sh       # positive + negative enforcement matrix

    The runtime OpenSSL client (use this, never /usr/bin/openssl):
      $OPENSSL_PREFIX/bin/openssl
EOF
