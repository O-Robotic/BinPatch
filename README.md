A tool to patch windows executables.

Currently supports code patches, data patches, import and export modifications.

A basic code patch looks like

```yaml
- type: code
  segment: .text
  mode: replace
  sig: 41 B8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 C7 44 24

  patch: |
    mov r8d, 200000h
```

A more complete set of examples can be found in https://github.com/O-Robotic/r5apex_patchset
This tool is currently in very early experimentation and certainly has weird cases of things being buggy with certain patches.
