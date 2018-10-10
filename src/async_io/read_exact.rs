use std::io;
use std::mem;

use futures::{Async, Future, Poll};
use tokio_io::AsyncRead;


#[derive(Debug)]
pub(crate) struct ReadExact<A, T> {
    state: State<A, T>,
}

#[derive(Debug)]
enum State<A, T> {
    Reading {
        a: A,
        buf: T,
        pos: usize,
        error: Option<io::Error>,
    },
    Empty,
}

pub(crate) fn read_exact<A, T>(a: A, buf: T) -> ReadExact<A, T>
where
    A: AsyncRead,
    T: AsMut<[u8]>,
{
    ReadExact {
        state: State::Reading {
            a: a,
            buf: buf,
            pos: 0,
            error: None,
        },
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
}

impl<A, T> Future for ReadExact<A, T>
where
    A: AsyncRead,
    T: AsMut<[u8]>,
{
    type Item = (A, T);
    type Error = (A, T, io::Error);

    fn poll(&mut self) -> Poll<(A, T), (A, T, io::Error)> {
        match self.state {
            State::Reading { ref mut a, ref mut buf, ref mut pos, ref mut error } => {
                let buf = buf.as_mut();
                while *pos < buf.len() {
                    let n = match a.poll_read(&mut buf[*pos..]) {
                        Ok(Async::Ready(n)) => n,
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Err(e) => {
                            *error = Some(e);
                            break;
                        },
                    };
                    *pos += n;
                    if n == 0 {
                        *error = Some(eof());
                        break;
                    }
                }
            }
            State::Empty => panic!("poll a ReadExact after it's done"),
        }

        match mem::replace(&mut self.state, State::Empty) {
            State::Reading { a, buf, error, .. } => match error {
                None    => Ok(Async::Ready((a, buf))),
                Some(e) => Err((a, buf, e)),
            },
            State::Empty => unreachable!(),
        }
    }
}
