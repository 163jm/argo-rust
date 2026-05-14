//! Wrap h2 RecvStream + SendStream into AsyncRead + AsyncWrite
//! so capnp-rpc's VatNetwork can use them directly.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::AsyncRead as FuturesAsyncRead;
use futures_util::AsyncWrite as FuturesAsyncWrite;
use h2::{RecvStream, SendStream};
use tracing::debug;

/// AsyncRead wrapper around h2::RecvStream
pub struct H2Reader {
    recv: RecvStream,
    buf:  BytesMut,
}

impl H2Reader {
    pub fn new(recv: RecvStream) -> Self {
        Self { recv, buf: BytesMut::new() }
    }
}

impl FuturesAsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Drain local buffer first
        if !self.buf.is_empty() {
            let n = out.len().min(self.buf.len());
            out[..n].copy_from_slice(&self.buf[..n]);
            self.buf.advance(n);
            return Poll::Ready(Ok(n));
        }

        // Poll h2 for next chunk
        match self.recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(0)), // EOF
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())))
            }
            Poll::Ready(Some(Ok(data))) => {
                let _ = self.recv.flow_control().release_capacity(data.len());
                let n = out.len().min(data.len());
                out[..n].copy_from_slice(&data[..n]);
                if data.len() > n {
                    self.buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(n))
            }
        }
    }
}

/// AsyncWrite wrapper around h2::SendStream<Bytes>
pub struct H2Writer {
    send: SendStream<Bytes>,
}

impl H2Writer {
    pub fn new(send: SendStream<Bytes>) -> Self {
        Self { send }
    }
}

impl FuturesAsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Reserve capacity
        match self.send.poll_capacity(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2 send stream closed",
                )));
            }
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())));
            }
            Poll::Ready(Some(Ok(n))) => {
                let to_send = n.min(buf.len());
                let data = Bytes::copy_from_slice(&buf[..to_send]);
                self.send
                    .send_data(data, false)
                    .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
                return Poll::Ready(Ok(to_send));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send
            .send_data(Bytes::new(), true)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
        Poll::Ready(Ok(()))
    }
}
