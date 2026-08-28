/* Rust's i686-pc-windows-gnu startup object expects these GCC frame
 * registration hooks. llvm-mingw's libunwind provides the unwind API but
 * intentionally omits the legacy registration entry points. */
void __register_frame_info(void *begin, void *object) {
    (void)begin;
    (void)object;
}

void __deregister_frame_info(void *begin) {
    (void)begin;
}
