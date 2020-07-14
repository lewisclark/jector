# Jector

Jector is a Windows tool that injects library files (.dll) into processes. This has numerous uses, such as overriding specific parts of an application's code or adding features.

## Usage
Jector must be invoked via the command line with 2 arguments. This can be done like so: `./jector <pid> <path to dll>`

This can also be used as a library for usage in your own project.

## How It Works
Jector doesn't use LoadLibrary like many other injectors. Instead, it allocates a buffer inside the target process and loads the target library into the buffer, like the Windows PE Loader does.

## Caveats
- Currently only supports injecting 64-bit libraries thus can only inject into 64-bit processes
- Only supports a single method of injection

## Todo
### Essential
- [ ] Create an Activation Context for the injected library
- [x] Perform base relocation if necessary
- [x] Resolve imports
- [ ] Resolve delayed imports
- [ ] Apply the correct memory protection to injected library sections
- [ ] Fix exception handling
- [ ] Initialize security cookie
- [ ] Initialize static TLS
- [ ] Fix TLS callbacks
### Non-essential
- [ ] Erase PE header
- [ ] Disallow the same library from being loaded more than once
- [ ] Support injecting 32-bit libraries into 32-bit processes
- [ ] Do base relocation outside of the loader routine
- [ ] Resolve imports outside of the loader routine
