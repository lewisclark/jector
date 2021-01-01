# Jector

Jector is a work-in-progress Windows tool that injects library files (.dll) into processes. This has numerous uses, such as overriding existing code or adding new features to an application.

## Usage
### Executable
```
USAGE:
    jector.exe [OPTIONS] --file <dll_file_path> <--pid <pid>|--window <window_name>>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f, --file <dll_file_path>              The DLL file to inject
    -m, --method <loadlibrary/manualmap>    The injection method to use [default: loadlibrary]
    -p, --pid <pid>                         The PID of the process to inject into
    -w, --window <window_name>              The name of the window to inject into
```

### Library
Jector can also be used as a library for usage in other projects.

## How It Works
Jector allocates a buffer inside the target process and loads the chosen dynamic-link library into the buffer as the Windows PE Loader does. The advantage of this method over using LoadLibrary or other library invocation routines is the added flexibility and customizability.