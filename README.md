ps4-np-hooks
============

Minimal PS4 (Orbis OS) NP hook / stub module.

Hooks a large subset of NP, UserService, Auth, Commerce and WordFilter
functions and returns fixed values so titles can run without real PSN
connectivity.

Intended for reverse engineering, research and offline testing.


Overview
--------

- Forces NP to report "online" and "logged in"
- Returns a fixed Online ID
- Stubs NP Auth async requests
- Auto-completes Commerce dialogs
- Always authorizes PS Plus
- Disables word filtering
- Emulates bandwidth test results
- Bypasses parental control checks

No real PSN communication is performed.


Use cases
---------

- Offline testing of NP-dependent titles
- Reverse engineering NP flows
- Debugging games that hang on PSN checks
- SPRX / payload experimentation


Non-goals
---------

- Not real PSN functionality
- Not online play
- Not intended for cheating or piracy


Technical notes
---------------

- Direct inline jump patching
- Memory protection via sceKernelMprotect
- Hooks applied to hardcoded system addresses
- No syscall emulation
- Designed as an injectable .sprx module


Build / usage
-------------

Requirements:
- Jailbroken PS4
- OpenOrbis or Orbis SDK
- .sprx loader

Steps:
1. Build as .sprx
2. Inject at runtime
3. Hooks are applied automatically
4. System notification confirms success


Disclaimer
----------

For research and educational purposes only.
Use at your own risk.


License
-------

MIT
