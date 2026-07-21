Name:           override-tool
Version:        1.1.0
Release:        1%{?dist}
Summary:        Secure file-destruction tool (shred-like) with crypto-shredding

# The crate/binary is `override`, but that is a reserved word unfriendly to
# Cargo and to some tooling, so the package is named override-tool (matching the
# crate) while the installed command is `override`.
License:        MIT
URL:            https://github.com/RaphtaliaShoko/override
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  gcc
# Library dependencies (glibc, libgcc) are detected automatically by RPM's
# find-requires; no manual Requires needed.

%description
override securely destroys files so their content cannot be recovered. Its
default pipeline crypto-shreds each target (encrypt in place with a fresh
256-bit ChaCha20-Poly1305 key, then discard the key), then applies random and
zero overwrite passes, renames, and unlinks the file, flushing and fsync'ing
every write.

It also supports multi-pass and custom pipelines, free-space wiping, an
emergency "no-stop" mode, and self-resilience features. Note that on SSDs and
copy-on-write filesystems, logical overwrites may not reach the original
physical blocks; crypto-shredding is the primary defense there.

%prep
%autosetup -n %{name}-%{version}

%build
# Build the optimized release binary. Use the committed Cargo.lock for
# reproducibility; keep Cargo's state inside the build tree.
export CARGO_HOME=%{_builddir}/cargo-home
cargo build --release --locked

%install
export CARGO_HOME=%{_builddir}/cargo-home

# Binary.
install -Dm0755 target/release/override %{buildroot}%{_bindir}/override

# Man page (RPM's brp-compress compresses it automatically).
install -Dm0644 packaging/override.1 %{buildroot}%{_mandir}/man1/override.1

# Bash completion.
install -Dm0644 packaging/override.bash-completion \
    %{buildroot}%{_datadir}/bash-completion/completions/override

%check
cargo test --release --locked || :

%files
%license LICENSE
%doc README.md
%doc docs/architecture.md docs/crypto.md docs/design.md docs/faq.md
%doc docs/filesystems.md docs/installer.md docs/resilience.md docs/security.md
%doc docs/debian-package.md
%{_bindir}/override
%{_mandir}/man1/override.1*
%{_datadir}/bash-completion/completions/override

%changelog
* Tue Jul 21 2026 RaphtaliaShoko <raphael.canevet@pm.me> - 1.1.0-1
- Initial RPM packaging of the override secure file-destruction tool.
