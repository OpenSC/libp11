---
name: Other bug report
about: Report a bug
labels: bug
---

<!--
Thank you for your bug report.
Note: Please search to see if an issue already exists for the bug you encountered.
-->

### Current Behavior
<!--
A concise description of what is happening.
Include error messages or incorrect results.
-->

### Expected Behavior
<!--
A concise description of what you expected to happen instead.
-->

### Steps To Reproduce & Observed Output
<!--
Provide exact, reproducible steps.
The full command line and complete stdout/stderr output are required.
Include the complete command, exactly as executed.
-->
- Full command line used: <!-- e.g. `openssl pkeyutl` -->
- Full stdout/stderr output: <!-- Paste the complete, unmodified output -->

### PKCS#11 Spy log
<!--
PKCS#11 trace logs are very helpful for diagnosis.
Please provide logs captured with PKCS#11 Spy:
https://github.com/OpenSC/Wiki/blob/master/Using-OpenSC.md
-->

### Environment
- Operating system and version (e.g. Ubuntu 24.04):
- Architecture (x86_64, arm64, etc.):
- PKCS#11 module used:
- Token / HSM type:

### Versions
<!--
Please verify that the issue is reproducible with the current upstream master.
-->
- libp11 built from:
  - [ ] upstream master
  - [ ] upstream release (tag):
  - [ ] distribution package (name and version):
- PKCS#11 module and version:
- `openssl version -a`

### Configuration / Settings
<!--
Anything that could affect signing or verification:
- Custom OpenSSL configuration
- Engine / provider settings
- Environment variables (OPENSSL_CONF, etc.)
-->

### Reproducibility
- [ ] Reproducible with a different PKCS#11 module:

### Files / Artifacts
<!--
Attach files if possible or mention that you will share them privately.
-->

### Anything else
<!--
Links, references, related issues, workarounds or additional observations.
-->
