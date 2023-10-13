BoringTUN.py [![Unlicensed work](https://raw.githubusercontent.com/unlicense/unlicense.org/master/static/favicon.png)](https://unlicense.org/)
============
~~[wheel (GitLab)](https://gitlab.com/KOLANICH-libs/BoringTUN.py/-/jobs/artifacts/master/raw/dist/BoringTUN-0.CI-py3-none-any.whl?job=build)~~
~~[wheel (GHA via `nightly.link`)](https://nightly.link/KOLANICH-libs/BoringTUN.py/workflows/CI/master/BoringTUN-0.CI-py3-none-any.whl)~~
~~![GitLab Build Status](https://gitlab.com/KOLANICH-libs/BoringTUN.py/badges/master/pipeline.svg)~~
~~![GitLab Coverage](https://gitlab.com/KOLANICH-libs/BoringTUN.py/badges/master/coverage.svg)~~
~~[![GitHub Actions](https://github.com/KOLANICH-libs/BoringTUN.py/workflows/CI/badge.svg)](https://github.com/KOLANICH-libs/BoringTUN.py/actions/)~~
[![Libraries.io Status](https://img.shields.io/librariesio/github/KOLANICH-libs/BoringTUN.py.svg)](https://libraries.io/github/KOLANICH-libs/BoringTUN.py)
[![Code style: antiflash](https://img.shields.io/badge/code%20style-antiflash-FFF.svg)](https://codeberg.org/KOLANICH-tools/antiflash.py)

**We have moved to https://codeberg.org/KOLANICH-libs/BoringTUN.py, grab new versions there.**

Under the disguise of "better security" Micro$oft-owned GitHub has [discriminated users of 1FA passwords](https://github.blog/2023-03-09-raising-the-bar-for-software-security-github-2fa-begins-march-13/) while having commercial interest in success and wide adoption of [FIDO 1FA specifications](https://fidoalliance.org/specifications/download/) and [Windows Hello implementation](https://support.microsoft.com/en-us/windows/passkeys-in-windows-301c8944-5ea2-452b-9886-97e4d2ef4422) which [it promotes as a replacement for passwords](https://github.blog/2023-07-12-introducing-passwordless-authentication-on-github-com/). It will result in dire consequencies and is competely inacceptable, [read why](https://codeberg.org/KOLANICH/Fuck-GuanTEEnomo).

If you don't want to participate in harming yourself, it is recommended to follow the lead and migrate somewhere away of GitHub and Micro$oft. Here is [the list of alternatives and rationales to do it](https://github.com/orgs/community/discussions/49869). If they delete the discussion, there are certain well-known places where you can get a copy of it. [Read why you should also leave GitHub](https://codeberg.org/KOLANICH/Fuck-GuanTEEnomo).

---

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
