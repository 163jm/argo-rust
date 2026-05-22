//! Wrap h2 RecvStream + SendStream as futures AsyncRead + AsyncWrite
//! for capnp-rpc VatNetwork.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::AsyncRead;
use futures_util::AsyncWrite;
use h2::{RecvStream, SendStream};

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

impl AsyncRead for H2Reader {
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

        match self.recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())
            )),
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
///
/// send_data() can be called without reserving capacity — h2 buffers it
/// and sends when flow control window opens. This is the correct approach.
pub struct H2Writer {
    send: SendStream<Bytes>,
}

impl H2Writer {
    pub fn new(send: SendStream<Bytes>) -> Self {
        Self { send }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // send_data buffers internally if no flow-control window is available.
        // This is safe and correct — h2 will flush when window opens.
        let data = Bytes::copy_from_slice(buf);
        match self.send.send_data(data, false) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())
            )),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.send.send_data(Bytes::new(), true) {
            Ok(()) | Err(_) => Poll::Ready(Ok(())),
        }
    }
}
