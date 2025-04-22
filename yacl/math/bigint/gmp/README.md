## Using GMP library installed on your system

Since The GNU MP Library (https://gmplib.org/) is licensed under GNU LGPL v3 (https://www.gnu.org/licenses/lgpl-3.0.en.html#license-text),
YACL dynamically links to it at runtime.

### Install GMP library on your system

To install GMP library on your system, you can use the following commands:

##### On Ubuntu:
```bash
sudo apt-get install libgmp-dev
```

##### On CentOS:
```bash
sudo yum install gmp-devel
```

##### On macOS:
```
brew install gmp
```

### Compile YACL with GMP headers

#### Enable GMP support
To enable GMP support when compiling YACL, use the `--config=gmp` option with Bazel, as shown below:
```bash
bazel build --config gmp //...
```

#### Resolving Compilation Errors
If you encounter a compilation error such as `fatal error: 'gmp.h' file not found"`, it indicates that the compiler
is unable to locate the GMP headers. To resolve this issue, you can set the header path using the following steps:

##### On Linux:
Place the GMP headers in the `/usr/local/include` directory and set their path by configuring the `CPLUS_INCLUDE_PATH`
environment variable as follows:
```bash
export CPLUS_INCLUDE_PATH=/usr/local/include
```

##### On macOS:
Copy the GMP header files to the default include path using the following command:
```bash
sudo cp /opt/homebrew/include/gmp* /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include/
```
