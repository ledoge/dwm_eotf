# About
This is a proof of concept for changing the EOTF/gamma that Windows uses when converting SDR content to HDR. By patching shaders in DWM's memory, the sRGB EOTF is effectively replaced with a "normal" gamma EOTF.

# Usage
Simply run `dwm_eotf.exe`. Note that it will kill the DWM process (which Windows will restart automatically), which can cause issues with some applications until they are restarted.

If you want to use a different gamma value than 2.4, you can pass it as an argument, e.g. `dwm_eotf.exe 2.2`.

Additionally, you can scale the SDR brightness level by a factor. For example, run `dwm_eotf.exe 2.2 0.5` and set the SDR slider to 0% (= 80 nits) to get 2.2 gamma output with 40 nits peak brightness. Note that some elements of Windows will show artifacts when you do this, so it's not really recommended.

# Known issues
* Chromium-based browsers output everything in scRGB if any wide-gamut or HDR content is visible or open in another tab. When this happens, the browser's color management applies the sRGB EOTF to all sRGB content, which this tool cannot do anything against.
