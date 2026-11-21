# Connect a debugger

sleuthre connects to targets that speak the GDB Remote Serial Protocol: `gdbserver`, QEMU's
gdbstub, and LLDB's platform server are the common cases. The debugger panel supports attach,
launch, stepping, registers, memory, breakpoints, and watchpoints.

## Prerequisites

- A target stub listening on a TCP address, for example `gdbserver :1234 ./program`.
- The binary open in sleuthre so addresses, architecture, and symbols line up.
- Debug symbols if you want source-level stepping; see
  [Use debug symbols](use-debug-symbols.md).

## Connect to a running stub

1. Open **Debugger → Open debugger panel**.
2. Keep **Transport** set to `GDB Remote`.
3. Enter the stub address in **Address**, in `host:port` form, for example `127.0.0.1:1234`.
4. Click **Connect**.

To attach to a process managed by the stub, enter its PID in **PID** and click **Attach** instead.
The PID is used for that connection only and is not stored in a saved profile.

Use the **Arch** selector if the project architecture does not match the target. The default is the
open project's architecture.

## Launch a local target (Linux)

On Linux, the **Local launch** transport starts a `gdbserver` child process, connects to it, and
reaps the child on disconnect.

1. Set **Transport** to `Local launch`.
2. Choose the executable with **Browse**.
3. Enter arguments, separated by spaces.
4. Click **Launch**.

The status line reports the assigned port and the address field is updated. The launch button is
disabled on non-Linux hosts because the implementation depends on a local `gdbserver`.

## Step and inspect

| Control | Effect |
|---|---|
| **Step Into** | Step one instruction, following calls |
| **Step Over** | Step over a call |
| **Step Out** | Run until the current frame returns |
| **Continue** | Resume until a breakpoint, watchpoint, signal, or exit |
| **Stop** | Interrupt an in-flight continue |
| **Refresh** | Re-read registers, memory, threads, and the current stop reason |
| **Step Source** | Advance to the next source line when DWARF line info is available |

The register dump and memory inspector show the target's current state. When the stub reports more
than one thread, a **Thread** selector appears; breakpoints can be scoped to the selected thread
with **this thread**.

## Breakpoints and watchpoints

Enter an address in **BP @** and choose:

- **+ Set** — software breakpoint.
- **+ Set HW** — hardware breakpoint.
- **+ Watch W**, **+ Watch R**, **+ Watch RW** — write, read, and read/write watchpoints on the
  address.

Active breakpoints are listed with a kind tag (`sw`, `hw`, `wp-w`, `wp-r`, `wp-rw`). Click the
small **x** next to one to clear it.

The disassembly context menu also offers **Set Breakpoint Here** and **Set Hardware BP Here** when
a debugger is connected.

## Disconnect

Click **Disconnect**. sleuthre detaches from the stub and, for a local launch, terminates the
`gdbserver` child it started.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Connect failed` | No stub at the address, wrong port, or a firewall blocking the loopback connection |
| Registers look wrong | Wrong architecture selected; set **Arch** to the target architecture |
| No source lines | The binary has no DWARF line table, or debug-info extraction was skipped |
| Step Source is missing | No source-line information is loaded for this project |

## Related

- [GUI reference](../reference/gui.md)
- [Use debug symbols](use-debug-symbols.md)
- [MCP server](../reference/mcp-server.md) — the debugger is GUI-only; MCP exposes static analysis
  tools.
