use dns_resolver::dns::{self, types::TYPE_A};

fn main() {
    println!("Result -> {:?}", dns::resolve("www.facebook.com", TYPE_A));
}
