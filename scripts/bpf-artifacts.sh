#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

case "$(uname -s):$(uname -m)" in
    Darwin:arm64) target=aarch64-macos; digest=3cc2bab367e185cdfb27501c4b30b1b0653c28d9f73df8dc91488e66ece5fa6b ;;
    Darwin:x86_64) target=x86_64-macos; digest=375b6909fc1495d16fc2c7db9538f707456bfc3373b14ee83fdd3e22b3d43f7f ;;
    Linux:aarch64) target=aarch64-linux; digest=958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f ;;
    Linux:x86_64) target=x86_64-linux; digest=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 ;;
    *) echo "Unsupported Zig host platform" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
curl -fsSL --retry 2 "https://ziglang.org/download/0.15.2/zig-$target-0.15.2.tar.xz" -o "$tmp/zig.tar.xz"
curl -fsSL --retry 2 "https://codeload.github.com/libbpf/libbpf/tar.gz/refs/tags/v1.5.0" -o "$tmp/libbpf.tar.gz"
(
    cd "$tmp"
    printf '%s  %s\n' "$digest" zig.tar.xz \
        53492aff6dd47e4da04ef5e672d753b9743848bdb38e9d90eafbe190b7983c44 libbpf.tar.gz |
        shasum -a 256 -c
)
mkdir -p "$tmp/zig" "$tmp/include/bpf" "$tmp/generated"
tar -xf "$tmp/zig.tar.xz" -C "$tmp/zig" --strip-components 1
tar -xf "$tmp/libbpf.tar.gz" -C "$tmp/include/bpf" --strip-components 2 \
    libbpf-1.5.0/src/bpf_helpers.h libbpf-1.5.0/src/bpf_helper_defs.h libbpf-1.5.0/src/bpf_endian.h
cat > "$tmp/zig-cc" <<'WRAPPER'
#!/bin/sh
for arg do
    shift
    case "$arg" in
        bpfel|bpfeb) arg="$arg-freestanding" ;;
    esac
    set -- "$@" "$arg"
done
exec "$(dirname "$0")/zig/zig" cc "$@"
WRAPPER
chmod +x "$tmp/zig-cc"
export ZIG_LOCAL_CACHE_DIR="$tmp/zig-local"
export ZIG_GLOBAL_CACHE_DIR="$tmp/zig-global"
make generate CLANG="$tmp/zig-cc" BPF_OUTPUT_DIR="$tmp/generated" \
    LIBBPF_CFLAGS="-I$tmp/include -ffile-prefix-map=$tmp/include=/usr/include"
for path in "$tmp"/generated/networkstats_bpf*; do
    name=${path##*/}
    if [ "${1:-check}" = "update" ]; then
        cp "$path" "internal/bpf/$name"
    elif ! cmp -s "$path" "internal/bpf/$name"; then
        echo "Stale BPF artifact: $name. Run make generate-pinned." >&2
        exit 1
    fi
done
