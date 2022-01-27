BoringTUN.py [![Unlicensed work](https://raw.githubusercontent.com/unlicense/unlicense.org/master/static/favicon.png)](https://unlicense.org/)
============
~~[wheel (GitLab)](https://gitlab.com/KOLANICH-libs/BoringTUN.py/-/jobs/artifacts/master/raw/dist/BoringTUN-0.CI-py3-none-any.whl?job=build)~~
~~[wheel (GHA via `nightly.link`)](https://nightly.link/KOLANICH-libs/BoringTUN.py/workflows/CI/master/BoringTUN-0.CI-py3-none-any.whl)~~
~~![GitLab Build Status](https://gitlab.com/KOLANICH-libs/BoringTUN.py/badges/master/pipeline.svg)~~
~~![GitLab Coverage](https://gitlab.com/KOLANICH-libs/BoringTUN.py/badges/master/coverage.svg)~~
~~[![GitHub Actions](https://github.com/KOLANICH-libs/BoringTUN.py/workflows/CI/badge.svg)](https://github.com/KOLANICH-libs/BoringTUN.py/actions/)~~
[![Libraries.io Status](https://img.shields.io/librariesio/github/KOLANICH-libs/BoringTUN.py.svg)](https://libraries.io/github/KOLANICH-libs/BoringTUN.py)
[![Code style: antiflash](https://img.shields.io/badge/code%20style-antiflash-FFF.svg)](https://codeberg.org/KOLANICH-tools/antiflash.py)

Python bindings to [BoringTUN](https://github.com/cloudflare/boringtun) using `ctypes`. You need a prebuilt shared library.

Since `ctypes.py` contains docstrings from boringtun library for everyones' convenience, it is copyrighted by CloudFlare. The rest of files are under Unlicense.

While the library functionality is much richer, most of it is not exposed as API available to C.

The exposed stuff:

* `Noise` protocol
* key generation.

Not currently exposed stuff you will have to reimplement yourself:

* Parsing of config toml files.
* Stuff related to the following config entries:
	* `Interface.ListenPort`
	* `Peer.AllowedIPs`
	* `Peer.Endpoint`

Tutorial is available as [`./tutorial.ipynb`](./tutorial.ipynb)[![NBViewer](https://nbviewer.org/static/ico/ipynb_icon_16x16.png)](https://nbviewer.org/urls/codeberg.org/KOLANICH-libs/BoringTUN.py/raw/branch/master/tutorial.ipynb) .
