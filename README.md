# About
This is a POC for changing the EOTF/gamma that Windows uses when converting SDR content to HDR. By patching shaders in DWM's memory, the sRGB EOTF is effectively replaced with a "normal" gamma EOTF.

# Usage
Simply run `dwm_eotf.exe`. Note that it will kill the DWM process (which Windows will restart automatically), which can cause issues with some applications until they are restarted.

If you want to use a different gamma value than 2.4, you can pass it as an argument, e.g. `dwm_eotf.exe 2.2`.

# Known issues
* Edge seems to switch between rendering in SDR and HDR, causing flicker. Unclear if this can be fixed.
