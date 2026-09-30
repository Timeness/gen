# EVM Vanity Address Generator v3.0

A blazing-fast, multi-threaded Ethereum (EVM) vanity address generator written in C++.

```
   _____ _   _____ ________________  _________  ___   ___  
  |  ___| | / / _ |_  /__  /__  / |/_/  _ _ \/ _ | / _ \ 
  | |_  | |/ / __ |/ /  /  / /_  > _ \  __/ __ |/ // / 
  |  _| | / /_/ /___/  /_/  /_/ /_/\___/\__/_/ |_/____/  
  |_|   |_|\___/   /___/  /___/                           
```

## Features

- **Multi-threaded**: Uses all CPU cores automatically
- **Multi-pattern**: Search multiple patterns at once
- **Match modes**: Prefix, suffix, or anywhere in address
- **Case options**: Case-sensitive or case-insensitive
- **Batch processing**: Configurable batch sizes for maximum throughput
- **Auto-stop**: Stop after N results or N attempts
- **Live progress**: Real-time speed and attempt counter
- **Result saving**: Auto-save matching addresses to file
- **Pure C++**: No external crypto library needed (uses OpenSSL)
- **Custom Keccak-256**: Hand-optimized, unrolled Keccak-f[1600] implementation

## Requirements

| Requirement | Version |
|-------------|---------|
| g++         | 11+     |
| OpenSSL     | 3.0+    |
| pthread     | any     |
| Linux/macOS | any     |

### Check Requirements

```bash
g++ --version
openssl version
```

## Installation

### Step 1: Install Dependencies (if not already installed)

**Debian / Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
```

**Fedora / RHEL / CentOS:**
```bash
sudo dnf install -y gcc-c++ openssl-devel
```

**macOS:**
```bash
brew install openssl
```

**Arch Linux:**
```bash
sudo pacman -S gcc openssl
```

### Step 2: Download the Source

```bash
git clone <repo-url>
cd evm-vanity-generator
```

Or download `evm_vanity_v3.cpp` directly.

### Step 3: Compile

```bash
g++ -O3 -march=native -fopenmp -pthread evm_vanity_v3.cpp -o evm_vanity -lcrypto
```

**Explanation of flags:**

| Flag | Meaning |
|------|---------|
| `-O3` | Maximum optimization |
| `-march=native` | Optimize for your CPU architecture |
| `-fopenmp` | Enable OpenMP parallelization |
| `-pthread` | Enable POSIX threads |
| `-lcrypto` | Link OpenSSL crypto library |

### Step 4: Verify Installation

```bash
./evm_vanity -h
```

You should see the help message.

## Usage

### Basic Syntax

```bash
./evm_vanity [options] <pattern1> [pattern2] [pattern3] ...
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t <n>` | Number of threads | Auto-detect (CPU cores) |
| `-b <n>` | Batch size per thread | 256 |
| `-m <mode>` | Match mode: `prefix`, `suffix`, `anywhere` | `prefix` |
| `-c` | Case-sensitive matching | Disabled |
| `-o <file>` | Save results to file | `vanity_results.txt` |
| `-n <num>` | Stop after finding N results | Unlimited |
| `-a <num>` | Stop after N attempts | Unlimited |
| `-h` | Show help | - |

### Examples

#### 1. Simple prefix search (most common)

Find an address starting with `dead`:

```bash
./evm_vanity dead
```

Output: `0xdead...`

#### 2. Multiple patterns at once

Search for addresses starting with `cafe`, `dead`, OR `beef`:

```bash
./evm_vanity cafe dead beef
```

#### 3. Suffix match

Find an address ending with `beef`:

```bash
./evm_vanity -m suffix beef
```

Output: `...beef`

#### 4. Anywhere match

Find `1337` anywhere in the address:

```bash
./evm_vanity -m anywhere 1337
```

#### 5. Case-sensitive search

Only match uppercase `DEAD`:

```bash
./evm_vanity -c DEAD
```

#### 6. Use more threads

If you have 16 cores:

```bash
./evm_vanity -t 16 dead
```

#### 7. Increase batch size for more speed

```bash
./evm_vanity -t 16 -b 512 dead
```

#### 8. Stop after finding 5 results

```bash
./evm_vanity -t 8 -n 5 cafe
```

#### 9. Save results to a file

```bash
./evm_vanity -t 12 -o my_wallets.txt dead beef
```

#### 10. Stop after 10 million attempts

```bash
./evm_vanity -t 8 -a 10000000 dead
```

#### 11. Full power mode (all cores, big batch)

```bash
./evm_vanity -t $(nproc) -b 1024 -n 10 -o results.txt dead beef cafe food
```

## Output Format

When a match is found, it prints:

```
Address:  0xdeadbeef1234...
PrivKey:  0xabc123...
```

Saved file format (`vanity_results.txt`):

```
# EVM Vanity Addresses
# ====================

Address:  0xdeadbeef...
PrivKey:  0x...

Address:  0xcafe1234...
PrivKey:  0x...
```

## Performance Tips

### 1. Match Shorter Patterns

| Pattern Length | Approx. Time (at 5,000 addr/s) |
|----------------|--------------------------------|
| 3 chars        | ~1 second                      |
| 4 chars        | ~1 minute                      |
| 5 chars        | ~15 minutes                    |
| 6 chars        | ~4 hours                       |
| 7 chars        | ~2.5 days                      |

### 2. Use More Threads

```bash
./evm_vanity -t $(nproc) dead
```

`$(nproc)` automatically uses all CPU cores.

### 3. Increase Batch Size

Larger batches = less overhead:

```bash
./evm_vanity -t 16 -b 1024 dead
```

### 4. Use Case-Insensitive Mode (default)

Case-insensitive is faster because it matches more addresses:

```bash
./evm_vanity dead     # faster (matches DEAD, Dead, dEaD, etc.)
./evm_vanity -c DEAD # slower (only matches DEAD)
```

### 5. Multiple Patterns = More Chances

```bash
./evm_vanity dead beef cafe food  # 4x more chances to find a match
```

## Expected Speed

| Setup | Approx. Speed |
|-------|---------------|
| 4 threads, default batch | ~4,500 addr/s |
| 8 threads, batch 512 | ~8,000 addr/s |
| 16 threads, batch 1024 | ~15,000 addr/s |
| With libsecp256k1 | ~100,000+ addr/s |

Speed depends on your CPU. Newer CPUs with AVX2 will be faster.

## Optional: Install libsecp256k1 for 10x+ Speed

If you want maximum performance, install `libsecp256k1` (Bitcoin Core's library):

### Build from Source

```bash
# Install dependencies
sudo apt-get install -y autoconf libtool build-essential

# Clone and build
cd /tmp
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-recovery --enable-experimental --enable-module-ecdh
make -j$(nproc)
sudo make install
sudo ldconfig

# Verify
pkg-config --exists libsecp256k1 && echo "Installed!"
```

> Note: The current version uses OpenSSL. For libsecp256k1 integration, code modifications are needed.

## Troubleshooting

### "Unable to locate package libsecp256k1-dev"

This is normal. `libsecp256k1` is not in standard repos. Build from source (see above) or use the OpenSSL version (already included).

### Compilation errors with OpenSSL

Make sure OpenSSL development headers are installed:

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# Fedora
sudo dnf install openssl-devel
```

### Slow speed

1. Increase threads: `-t $(nproc)`
2. Increase batch size: `-b 1024`
3. Use shorter patterns
4. Close other CPU-intensive programs

### "No patterns provided"

You must provide at least one hex pattern:

```bash
./evm_vanity dead   # correct
./evm_vanity        # error: no pattern
```

### Pattern must be valid hex

Only hex characters (0-9, a-f, A-F) are allowed:

```bash
./evm_vanity dead   # valid
./evm_vanity xyz    # invalid (x, y, z not hex)
```

## How It Works

1. **Generate random private key** using OpenSSL's secp256k1
2. **Derive public key** from private key
3. **Hash public key** with Keccak-256 (Ethereum's hash)
4. **Take last 20 bytes** = EVM address
5. **Check if address matches** any of the given patterns
6. **Repeat** until a match is found or stopped

## Security Notes

- Private keys are generated locally on your machine
- No network calls are made
- Keys are not stored unless you use `-o` flag
- Always verify addresses before using them
- Keep your private keys secure and never share them

## License

MIT License - Use at your own risk.

## Author

Built with speed in mind.
