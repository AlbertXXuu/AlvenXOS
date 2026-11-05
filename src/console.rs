use core::fmt::{self, Write};

struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            crate::arch::putchar(byte);
        }
        Ok(())
    }
}

pub fn write(args: fmt::Arguments<'_>) {
    Console.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::console::write(format_args!($($arg)*)) };
}
