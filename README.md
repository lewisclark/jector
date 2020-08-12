# Jector

Jector is a work-in-progress Windows tool that injects library files (.dll) into processes. This has numerous uses, such as overriding existing code or adding new features to an application.

## Usage
### Executable
Jector must be invoked via the command line with 3 arguments. This can be done like so: `./jector <pid> <path to dll> <injection method>`. To view a list of available injection methods, run jector without any arguments.

### Library
Jector can also be used as a library for usage in other projects.

## How It Works
Jector allocates a buffer inside the target process and loads the chosen dynamic-link library into the buffer as the Windows PE Loader does. The advantage of this method over using LoadLibrary or other library invocation routines is the added flexibility and customizability.

## Caveats
- Currently only supports injecting 64-bit libraries thus can only inject into 64-bit processes

## Todo
### Essential
- [ ] Create an Activation Context for the injected library
- [x] Perform base relocation if necessary
- [x] Resolve imports
- [ ] Resolve delayed imports
- [x] Apply the correct memory protection to injected library sections
- [x] Fix exception handling
- [ ] Initialize security cookie
- [x] Initialize static TLS
- [ ] Fix TLS callbacks
- [ ] Handle other base relocation types
### Non-essential
- [ ] Logging
- [ ] Support injecting 32-bit libraries into 32-bit processes
- [ ] Disallow the same library from being loaded more than once
- [ ] Erase PE header
- [x] Do base relocation outside of the loader routine
- [x] Resolve imports outside of the loader routine
