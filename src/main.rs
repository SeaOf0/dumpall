fn main() {
    if let Err(error) = dumpall::run() {
        eprintln!("dumpall: {error}");
        std::process::exit(1);
    }
}
