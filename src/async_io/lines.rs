use std::io::{self, BufRead};
use std::mem;

use futures::{Async, Poll, Stream};
use tokio_io::AsyncRead;


#[derive(Debug)]
pub(crate) struct Lines<A> {
    state: State<A>,
}

#[derive(Debug)]
enum State<A> {
    Reading {
        io: A,
        line: String,
        finished: bool,
        error: Option<io::Error>,
    },
    IoOnly {
        io: A,
    },
    Empty,
}

pub(crate) fn lines<A>(a: A) -> Lines<A>
where
    A: AsyncRead + BufRead,
{
    Lines {
        state: State::Reading {
            io: a,
            line: String::new(),
            finished: false,
            error: None,
        },
    }
}

impl<A> Lines<A> {
    pub(crate) fn into_inner(self) -> A {
        match self.state {
            State::Reading { io, .. } => io,
            State::IoOnly { io } => io,
            State::Empty => unreachable!(),
        }
    }
}

impl<A> Stream for Lines<A>
where
    A: AsyncRead + BufRead,
{
    type Item = String;
    type Error = (A, io::Error);

    fn poll(&mut self) -> Poll<Option<String>, (A, io::Error)> {
        match self.state {
            State::Reading { ref mut io, ref mut line, ref mut finished, ref mut error } => {
                match io.read_line(line) {
                    Ok(n) => {
                        if n == 0 && line.len() == 0 {
                            *finished = true;
                        }
                        if line.ends_with("\n") {
                            line.pop();
                            if line.ends_with("\r") {
                                line.pop();
                            }
                        }
                    },
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(Async::NotReady);
                    },
                    Err(e) => {
                        *error = Some(e);
                    },
                };
            },
            State::IoOnly { .. } |
            State::Empty         => panic!("poll a Lines after it's done"),
        }

        match mem::replace(&mut self.state, State::Empty) {
            State::Reading { io, mut line, finished, error } => {
                if finished {
                    mem::replace(&mut self.state, State::IoOnly { io });
                    return Ok(Async::Ready(None));
                }

                match error {
                    None => {
                        let result = mem::replace(&mut line, String::new());
                        mem::replace(&mut self.state, State::Reading { io, line, finished, error });

                        Ok(Async::Ready(Some(result)))
                    },
                    Some(e) => Err((io, e)),
                }
            },
            State::IoOnly { .. } |
            State::Empty         => unreachable!(),
        }
    }
}
