use std::io;
use std::mem;

use futures::{Async, Future, Poll};
use tokio_io::AsyncWrite;


#[derive(Debug)]
pub(crate) struct WriteAll<A, T> {
    state: State<A, T>,
}

#[derive(Debug)]
enum State<A, T> {
    Writing {
        a: A,
        buf: T,
        pos: usize,
        error: Option<io::Error>,
    },
    Empty,
}

pub(crate) fn write_all<A, T>(a: A, buf: T) -> WriteAll<A, T>
where
    A: AsyncWrite,
    T: AsRef<[u8]>,
{
    WriteAll {
        state: State::Writing {
            a: a,
            buf: buf,
            pos: 0,
            error: None,
        },
    }
}

fn zero_write() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "zero-length write")
}

impl<A, T> Future for WriteAll<A, T>
where
    A: AsyncWrite,
    T: AsRef<[u8]>,
{
    type Item = (A, T);
    type Error = (A, T, io::Error);

    fn poll(&mut self) -> Poll<(A, T), (A, T, io::Error)> {
        match self.state {
            State::Writing { ref mut a, ref buf, ref mut pos, ref mut error } => {
                let buf = buf.as_ref();
                while *pos < buf.len() {
                    let n = match a.poll_write(&buf[*pos..]) {
                        Ok(Async::Ready(n)) => n,
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(e) => {
                            *error = Some(e);
                            break;
                        },
                    };
                    *pos += n;
                    if n == 0 {
                        *error = Some(zero_write());
                        break;
                    }
                }
            },
            State::Empty => panic!("poll a WriteAll after it's done"),
        }

        match mem::replace(&mut self.state, State::Empty) {
            State::Writing { a, buf, error, .. } => match error {
                None    => Ok(Async::Ready((a, buf))),
                Some(e) => Err((a, buf, e)),
            },
            State::Empty => unreachable!(),
        }
    }
}
