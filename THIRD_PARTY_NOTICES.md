# Licensing and upstream provenance

The original Android application, Python host/verifier/configurator, native
launcher, build scripts and documentation are MIT licensed; see [LICENSE](LICENSE).
This does not relicense the upstream code represented in the KDE patches.

- `packaging/kde-repo/` contains Gentoo packaging derived from Gentoo Authors'
  GPL-2.0-only ebuilds and the kdesu-only split patch by Andreas Sturmlechner.
- The kdesu integration patch targets KDE `kde-cli-tools` **6.7.2**. Modified and
  added kdesu C++ files retain their Artistic-2.0 notices, including Geert Jansen's
  existing copyright. The upstream distribution contains other licensed components;
  consult its per-file SPDX notices when redistributing a complete build.
- The Codex SVG included inside the patch is from **LobeHub**, copyright 2023,
  under MIT. Its complete notice is retained as `kdesu/icons/LICENSE.codex` when
  the patch is applied. Inclusion does not imply endorsement.
- [Artistic-2.0](LICENSES/Artistic-2.0.txt) and
  [GPL-2.0-only](LICENSES/GPL-2.0-only.txt) texts are retained from the upstream
  KDE release archive.

Upstream: <https://invent.kde.org/plasma/kde-cli-tools>.
This is a downstream project, not an official KDE release or Android security product.
