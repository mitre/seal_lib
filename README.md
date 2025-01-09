# seal_lib

seal_lib is a rust library for SEAL developers to put shared code in. 

## Version
1.7.1

## Installation

Include this library in any SEAL project with the following line in your Cargo.toml
```
seal_lib = { git = "ssh://git@github.com:mitre/seal_lib.git" }
```

You might need to help Cargo authenticate with gitlab when trying to install this library.

On Mac/Linux you can do the below command to add your Gitlab SSH keys to ssh-agent
```
ssh-add ~/.ssh
```

If those steps didn't work, or you're on windows, check this link for more information:
[https://doc.rust-lang.org/cargo/appendix/git-authentication.html](https://doc.rust-lang.org/cargo/appendix/git-authentication.html)

### Offline Installation

If you need to install a rust project that uses this repo as a dependency, but you're offline or don't have MITRE gitlab
access, you can tell Cargo to use a local copy of seal_lib using the following steps:
1. Clone a local copy of this repository to your offline machine
1. Add this snippet to the `Cargo.toml`, replacing seal_lib_path with the relative path to the local copy.
```
[patch.'https://github.com/mitre/seal_lib.git']
seal_lib = { path = "seal_lib_path" }
```
## Running the ILF Checker Binary

Run `cargo build` to build the binary file.

```
USAGE:
    ilf_checker --ilf-file <ilf-file>
```

Pass the path to an ILF file as input. The tool will print parse errors if any ILF are malformed.

```
ilf_checker --ilf-file /path/to/file.ilf
```

## License

This software is licensed under the Apache 2.0 license.

## Public Release

> [!NOTE]
> Approved for Public Release; Distribution Unlimited. Public Release Case
> Number 24-3961.