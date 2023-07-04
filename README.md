# About
This is a proof of concept for changing the EOTF/gamma that Windows uses when converting SDR content to HDR. By patching shaders in DWM's memory, the sRGB EOTF is effectively replaced with a "normal" gamma EOTF.

# Usage
Simply run `dwm_eotf.exe`. Note that it will kill the DWM process (which Windows will restart automatically), which can cause issues with some applications until they are restarted.

If you want to use a different gamma value than 2.4, you can pass it as an argument, e.g. `dwm_eotf.exe 2.2`.

# Known issues
* Chromium-based browsers output everything in scRGB if any wide-gamut or HDR content is visible or open in another tab. When this happens, the browser's color management applies the sRGB EOTF to all sRGB content, which this tool cannot do anything against.
