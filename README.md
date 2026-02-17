PS4 NP / Orbis Network Hook Framework

⚠️ For research, learning, and reverse-engineering purposes only
This project is not intended for cheating, piracy, or abusing online services.

📌 Overview

This project implements a low-level hook framework for PlayStation 4 (Orbis OS) that intercepts and emulates a large portion of NP (Network Platform), UserService, Commerce, Auth, and WordFilter APIs.

The primary goal is to stub out NP dependencies in order to:

Run games offline that normally require PSN

Bypass NP availability, state, and Plus checks

Simulate NP Auth and async request flows

Assist in reverse-engineering PS4 network behavior

✨ Features
🔌 NP / UserService Hooks

sceNpCheckNpAvailability

sceNpGetState

sceNpGetOnlineId

sceNpGetAccountId

sceNpGetNpId

sceUserServiceGetEvent

Game Presence & State callbacks

✔️ Always reports online & logged-in state

🔐 NP Authentication (Auth)

sceNpAuthCreateAsyncRequest

sceNpAuthPollAsync

sceNpAuthGetAuthorizationCode

✔️ Fully emulated async lifecycle
✔️ Returns a fake authorization code
⚠️ No real PSN authentication occurs

🛒 NP Commerce / Store

sceNpCommerceDialogInitialize

sceNpCommerceDialogOpen

sceNpCommerceDialogUpdateStatus

sceNpCommerceDialogGetResult

PS Store icon hooks

✔️ Commerce dialogs auto-complete successfully
✔️ Games believe purchases/subscriptions are valid

🚀 Async NP Requests

sceNpCreateAsyncRequest

sceNpPollAsync

✔️ Requests complete immediately
✔️ Proper state transitions are preserved

📡 Bandwidth Test Emulation

sceNpBandwidthTestInitStart

sceNpBandwidthTestGetStatus

sceNpBandwidthTestShutdown

✔️ Fake but realistic bandwidth results

Download: 100 Mbps

Upload: 20 Mbps

👨‍👩‍👧 Parental Control & Account Info

sceNpGetParentalControlInfo

sceNpSetContentRestriction

sceNpCheckPlus

sceNpGetAccountCountry

sceNpGetAccountDateOfBirth

✔️ Adult account (18+)
✔️ No restrictions
✔️ PS Plus always authorized

🧼 Word Filter

sceNpWordFilterCreateTitleCtx

sceNpWordFilterCreateAsyncRequest

sceNpWordFilterSanitizeComment

sceNpWordFilterPollAsync

✔️ Word filtering disabled (input == output)

🧠 Design Notes

Uses direct inline jump patching (WriteJump)

Memory protection handled via sceKernelMprotect

No SDK stubs — hooks are applied to real system addresses

Designed for payload / sprx injection

Thread-safe enough for typical game NP usage

🧪 Tested Use-Cases

Games that hang on “Connecting to PSN”

Titles requiring PS Plus checks for offline modes

NP-dependent menus (store, presence, auth)

Reverse-engineering NP flows without Sony servers

⚙️ Build & Usage
Requirements

Jailbroken PS4

Orbis SDK / OpenOrbis

Payload or .sprx loader

C++17 compatible toolchain

Usage

Build as a .sprx

Inject or load the module at runtime

Hooks are applied automatically

Notification confirms success:

hooked successfully!

⚠️ Disclaimer

This software:

Does not connect to PlayStation Network

Does not provide real PSN functionality

Is intended strictly for offline use, debugging, and research

You are responsible for how you use it.
