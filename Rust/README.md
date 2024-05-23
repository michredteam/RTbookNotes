
# OffensiveRust

My experiments in weaponizing [Rust](https://www.rust-lang.org/) for implant development and general offensive operations.  

## Table of Contents

- [OffensiveRust](#offensiverust)
  * [Why Rust?](#why-rust)
  * [Examples in this repo](#examples-in-this-repo)
  * [Compiling the examples](#compiling-the-examples-in-this-repo)
  * [Compiling the examples in this repo](#Compiling-the-examples-in-this-repo)
  * [Cross Compiling](#cross-compiling)
  * [Optimizing executables for size](#optimizing-executables-for-size)
  * [Pitfalls I found myself falling into](#pitfalls-i-found-myself-falling-into)
  * [Interesting Rust Libraries](#interesting-Rust-libraries)
  * [Opsec](#Opsec)
  * [Other projects I have have made in Rust](#Other-projects-I-have-made-in-Rust)
  * [Projects in Rust that can be hepfull ](#Projects-in-Rust-that-can-be-hepfull )

## Why Rust?

- It is faster than languages like C/C++
- It is multi-purpose language, bearing excellent communities
- It has an amazing inbuilt dependency build management called Cargo
- It is LLVM based which makes it a very good candidate for bypassing static AV detection
- Super easy cross compilation to Windows from *nix/MacOS, only requires you to install the `mingw` toolchain, although certain libraries cannot be compiled successfully in other OSes.


## Compiling the examples in this repo

This repository does not provide binaries, you're gonna have to compile them yourself.  

[Install Rust](https://www.rust-lang.org/tools/install)  
Simply download the binary and install.

This repo was compiled in Windows 10 so I would stick to it. As mentioned OpenSSL binaries will have depencency issues that will require OpenSSL and perl to be installed.
For the TCP SSL client/server I recommend static build due to dependencies on the hosts you will execute the binaries.
For creating a project, execute:  
`cargo new <name>`
This will automatically create the structured project folders with:

```bash  
project
├── Cargo.toml
└── src
    └── main.rs
```

Cargo.toml is the file that contains the dependencies and the configuration for the compilation.
main.rs is the main file that will be compiled along with any potential directories that contain libraries.

For compiling the project, go into the project directory and execute:  
`cargo build`

This will use your default toolchain.
If you want to build the final "release" version execute:  
`cargo build --release`

For static binaries, in terminal before the build command execute:  
`"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"`  
`set RUSTFLAGS=-C target-feature=+crt-static`

In case it does not feel easy for you to read my code the way it is written,  
you can also you the below command inside the project directory to format it in a better way  
`cargo fmt`

Certain examples might not compile and give you some error, since it might require a nightly  
build of Rust with the latest features. To install it just do:  
`rustup default nightly`  



The easiest place to find the dependencies or [Crates](https://crates.io/) as they are called.






## OPSEC

- Even though Rust has good advantages it is quite difficult to get used to it and it ain't very intuitive.  
- Shellcode generation is another issue due to LLVM. I have found a few ways to approach this.  
[Donut](https://github.com/TheWover/donut) sometimes does generate shellcode that works but depending on how the project is made, it might not.  
In general, for shellcode generation the tools that are made should be made to host all code in .text segment,
which leads to this amazing 
There is a shellcode sample in this project that can show you how to structure your code for successfull shellcode generation.  
In addition, this project also has a shellcode generator that grabs the .text segment of a binary and
and dumps the shellcode after executing some patches.  
This project grabs from a specific location the binary so I made a fork that receives the path of the binary as an argument [here](https://github.com/trickster0/rust-windows-shellcode-custom).  
- Even if you remove all debug symbols, rust can still keep references to your home directory in the binary. The only way I've found to remove this is to pass the following flag: `--remap-path-prefix {your home directory}={some random identifier}`. You can use bash variables to get your home directory and generate a random placeholder: `--remap-path-prefix "$HOME"="$RANDOM"`. 
- Although for the above there is another way to remove info about the home directory by adding at the top of Cargo.toml  
`cargo-features = ["strip"]` .  
Since Rust by default leaves a lot of things as strings in the binary, I mostly use this [cargo.toml](../master/cargo.toml) to avoid them and also reduce size  
with build command   
`cargo build --release -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-pc-windows-msvc`
- also pointed out that depending on the imported libraries, stripping is not always consistent on hiding the home directory, so a combination of his solution to remap the path and use teh above cargo would work best. Try to be aware and check your binaries before executing them to your engagements for potential strings that are not stripped properly.
