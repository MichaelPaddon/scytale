//! The text every subcommand's `--help` ends with: how a value is
//! written and what the exit status means, so that no call needs the
//! manual to be read correctly.

pub const VALUES: &str = "\
Values:
  A key, nonce, tag, salt, signature or label is written with a prefix
  and never bare: hex:00ff.. (even count of digits, no 0x), file:PATH
  (raw bytes), fd:N (raw bytes from descriptor N), env:NAME (hex in
  the variable), str:TEXT (the text; not for a key). The algorithm
  fixes each length, and a value of another length is refused.

Output:
  --hex writes hex and a newline, --raw the bytes; the default is in
  the option's help.

Exit status:
  0 done; 1 a tag, signature or padding did not verify; 2 the request
  could not be carried out as asked; 3 anything else.

The manual, scytale(1), has the rest.";
