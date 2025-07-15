# syscall_tracer

> [!WARNING]
> This tool was created for fun and learning purposes only.

-   [Description](#description)
-   [Requirements](#requirements)
-   [Installation](#installation)
-   [Usage](#usage)

## Description

syscall_tracer is a simple Linux syscall tracer written in C for x86_64 programs.

It uses `ptrace` to intercept and log system calls executed by a target process.

## Requirements

- [gcc](https://gcc.gnu.org/)

## Installation

```console
# clone the repo
$ git clone https://github.com/utox39/syscall_tracer.git

# cd to the path
cd path/to/syscall_tracer

# Build syscall_tracer
make
```

## Usage

```console
usage: ./syscall_tracer <executable/program
```

```console
$ syscall_tracer ./hello
```

