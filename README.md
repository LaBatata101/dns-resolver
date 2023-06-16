# DNS resolver
This is a implementation of a very simple DNS resolver.

The only records types supported are `A` and `NS`.

## Code Example
```rust
use dns_resolver::dns::{self, types::TYPE_A};

fn main() {
    println!("Result -> {:?}", dns::resolve("twitter.com", TYPE_A));
}

```

# Running
```bash
$ git clone https://github.com/LaBatata101/dns-resolver && cd dns-resolver
$ cargo run
```
