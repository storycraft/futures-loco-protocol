use std::{
    io::{self, Cursor, ErrorKind, Read},
    mem,
    pin::Pin,
    task::{ready, Context, Poll},
};

use futures_io::{AsyncRead, AsyncWrite};
use loco_protocol::secure::{
    client::{LocoClientSecureLayer, ReadState as LayerReadState, rsa::RsaPublicKey},
    SecurePacket,
};
use rand::RngCore;

pub use loco_protocol::secure::client::rsa;

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct LocoSecureStream<T> {
        read_state: ReadState,
        write_state: WriteState,

        layer: LocoClientSecureLayer,

        #[pin]
        inner: T,
    }
}

impl<T> LocoSecureStream<T> {
    pub const MAX_IO_SIZE: u64 = 16 * 1024 * 1024;

    pub fn new(rsa_key: RsaPublicKey, inner: T) -> Self {
        let mut key = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut key);

        Self {
            read_state: ReadState::Pending,
            write_state: WriteState::Initial(rsa_key),

            layer: LocoClientSecureLayer::new(key),

            inner,
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead> AsyncRead for LocoSecureStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        loop {
            match mem::replace(this.read_state, ReadState::Corrupted) {
                ReadState::Pending => {
                    if let Some(packet) = this.layer.read() {
                        *this.read_state = ReadState::Reading(Cursor::new(packet.data));
                    } else {
                        if let LayerReadState::Header(header) = this.layer.read_state() {
                            if header.size as u64 - 16 > Self::MAX_IO_SIZE {
                                *this.read_state = ReadState::PacketTooLarge;
                                continue;
                            }
                        }

                        let mut read_buf = [0_u8; 1024];

                        *this.read_state = ReadState::Pending;

                        let read = ready!(this.inner.as_mut().poll_read(cx, &mut read_buf))?;
                        if read == 0 {
                            *this.read_state = ReadState::Done;
                            continue;
                        }

                        this.layer.read_buffer.extend(&read_buf[..read]);
                    }
                }

                ReadState::Reading(mut cursor) => {
                    let read = cursor.read(buf)?;

                    *this.read_state = if cursor.position() as usize == cursor.get_ref().len() {
                        ReadState::Pending
                    } else {
                        ReadState::Reading(cursor)
                    };

                    break Poll::Ready(Ok(read));
                }

                ReadState::PacketTooLarge => {
                    *this.read_state = ReadState::PacketTooLarge;

                    break Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "packet is too large",
                    )));
                }

                ReadState::Done => break Poll::Ready(Err(ErrorKind::UnexpectedEof.into())),

                ReadState::Corrupted => unreachable!(),
            }
        }
    }
}

impl<T: AsyncWrite> AsyncWrite for LocoSecureStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        loop {
            match mem::replace(this.write_state, WriteState::Corrupted) {
                WriteState::Initial(key) => {
                    this.layer.handshake(&key);

                    *this.write_state = WriteState::Pending;
                }

                WriteState::Pending => {
                    let data = if buf.len() as u64 > Self::MAX_IO_SIZE {
                        &buf[..Self::MAX_IO_SIZE as usize]
                    } else {
                        buf
                    };

                    let mut iv = [0_u8; 16];
                    rand::thread_rng().fill_bytes(&mut iv);

                    *this.write_state = WriteState::Writing(data.len());
                    this.layer.send(SecurePacket { iv, data });
                }

                WriteState::Writing(size) => {
                    let write_buffer = &mut this.layer.write_buffer;

                    loop {
                        let slice = {
                            let slices = write_buffer.as_slices();

                            if !slices.0.is_empty() {
                                slices.0
                            } else {
                                slices.1
                            }
                        };

                        match this.inner.as_mut().poll_write(cx, slice)? {
                            Poll::Ready(written) => {
                                write_buffer.drain(..written);
                            }

                            Poll::Pending => {
                                *this.write_state = WriteState::Writing(size);
                                return Poll::Pending;
                            }
                        }

                        if write_buffer.is_empty() {
                            *this.write_state = WriteState::Pending;
                            return Poll::Ready(Ok(size));
                        }
                    }
                }

                WriteState::Corrupted => unreachable!(),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }
}

#[derive(Debug)]
enum ReadState {
    Pending,
    Reading(Cursor<Box<[u8]>>),
    PacketTooLarge,
    Done,
    Corrupted,
}

#[derive(Debug)]
enum WriteState {
    Initial(RsaPublicKey),
    Pending,
    Writing(usize),
    Corrupted,
}
