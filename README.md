# PintOS

This is a group project we have done to study the operating system framework and related data structures and memory management.

PintOS is a simple operating system framework for the 80x86 architecture. It supports kernel threads, loading and running user programs, and a file system. This repository contains the source code, documentation, and test suites for PintOS.

## Project Structure

The repository is organized as follows:

- **`doc/`**: Documentation files, including technical specifications, development guides, and reference materials.
- **`src/`**: Source code for the PintOS kernel, user programs, and supporting libraries.
  - **`devices/`**: Device drivers (e.g., keyboard, timer, VGA).
  - **`examples/`**: Example user programs.
  - **`filesys/`**: File system implementation.
  - **`lib/`**: Utility libraries for kernel and user programs.
  - **`threads/`**: Thread management and synchronization primitives.
  - **`userprog/`**: User program loading and system call handling.
  - **`vm/`**: Virtual memory management.
- **`tests/`**: Test suites for verifying functionality (e.g., threads, user programs, file system).
- **`specs/`**: Reference materials for hardware specifications (e.g., VGA, keyboard).
- **`utils/`**: Utility scripts and tools for building and debugging PintOS.

## Features

- **Thread Management**: Supports kernel threads with priority scheduling.
- **User Programs**: Loads and executes user programs in a protected environment.
- **File System**: Implements a basic file system with support for files and directories.
- **Virtual Memory**: Manages memory allocation and paging for user programs.
- **Device Drivers**: Includes drivers for keyboard, timer, VGA, and other hardware.

## Getting Started

### Prerequisites

- A Unix-like environment (Linux or macOS recommended).
- GCC and GNU Make for building the project.
- QEMU or Bochs for emulating the 80x86 architecture.

### Building PintOS

1. Navigate to the `src/` directory:
   ```bash
   cd src/
   ```
2. Build the kernel and user programs:
   ```bash
   make
   ```

### Running PintOS

To run PintOS in an emulator (e.g., QEMU):
```bash
cd src/threads/
make qemu
```

## Testing

PintOS includes a comprehensive test suite. To run the tests:
```bash
cd src/tests/
make check
```

## Documentation

For detailed documentation, refer to the files in the `doc/` directory. Key documents include:
- `threads.texi`: Thread management and synchronization.
- `userprog.texi`: User program loading and system calls.
- `vm.texi`: Virtual memory management.

## License

PintOS is distributed under the [LICENSE](LICENSE) file in the root directory.

## Contributing

Contributions are welcome! Please refer to the [AUTHORS](AUTHORS) file for guidelines.

## Acknowledgments

PintOS was developed as part of academic coursework and is maintained by the community. Special thanks to all contributors listed in the [AUTHORS](AUTHORS) file.