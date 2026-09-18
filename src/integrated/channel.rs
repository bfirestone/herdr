use std::io::{self, BufRead};
pub(super) const INPUT_LIMIT: usize = 512 * 1024;
pub(super) const CONTROL_LIMIT: usize = 1024 * 1024;
pub(super) fn read_frame(reader: &mut impl BufRead, limit: usize) -> io::Result<serde_json::Value> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let length = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if frame.len() + length > limit {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let complete = available[length - 1] == b'\n';
        frame.extend_from_slice(&available[..length]);
        reader.consume(length);
        if complete {
            return serde_json::from_slice(&frame).map_err(io::Error::other);
        }
    }
}
pub(super) fn write_frame(
    writer: &mut impl std::io::Write,
    value: &impl serde::Serialize,
    limit: usize,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > limit {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    writer.write_all(&bytes)?;
    writer.flush()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_terminated_bounded_single_json_frame() {
        assert!(read_frame(&mut &b"{}"[..], 20).is_err());
        assert!(read_frame(&mut &b"{\"x\":1234}\n"[..], 5).is_err());
        assert!(read_frame(&mut &b"{} {}\n"[..], 20).is_err());
        assert_eq!(
            read_frame(&mut &b"{\"x\":\"a\\nb\"}\n"[..], 20).unwrap()["x"],
            "a\nb"
        );
    }
}

#[cfg(test)]
mod write_tests {
    use super::*;
    #[test]
    fn partial_body_failure_is_returned_without_replay() {
        struct Partial {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl std::io::Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls > 1 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                self.bytes.extend_from_slice(&bytes[..5]);
                Ok(5)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut partial = Partial {
            bytes: vec![],
            calls: 0,
        };
        assert!(write_frame(
            &mut partial,
            &serde_json::json!({"text":"secret"}),
            INPUT_LIMIT
        )
        .is_err());
        assert_eq!(partial.calls, 2);
        assert_eq!(partial.bytes.len(), 5);
    }
}
