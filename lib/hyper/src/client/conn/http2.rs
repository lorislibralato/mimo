//! HTTP/2 client connections

use std::error::Error as StdError;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
#[cfg(feature = "runtime")]
use std::time::Duration;

use http::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Body;
use crate::body::HttpBody;
use crate::common::{
    exec::{BoxSendFuture, Exec},
    task, Future, Pin, Poll,
};
use crate::proto;
use crate::rt::Executor;
use super::super::dispatch;

/// The sender side of an established connection.
pub struct SendRequest<B> {
    dispatch: dispatch::Sender<Request<B>, Response<Body>>,
}

/// A future that processes all HTTP state for the IO object.
///
/// In most cases, this should just be spawned into an executor, so that it
/// can process incoming and outgoing messages, notice hangups, and the like.
#[must_use = "futures do nothing unless polled"]
pub struct Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
    B: HttpBody + 'static,
{
    inner: (PhantomData<T>, proto::h2::ClientTask<B>),
}

/// A builder to configure an HTTP connection.
///
/// After setting options, the builder is used to create a handshake future.
#[derive(Clone, Debug)]
pub struct Builder {
    pub(super) exec: Exec,
    h2_builder: proto::h2::client::Config,
}

/// Returns a handshake future over some IO.
///
/// This is a shortcut for `Builder::new().handshake(io)`.
/// See [`client::conn`](crate::client::conn) for more.
pub async fn handshake<T>(
    io: T,
) -> crate::Result<(SendRequest<crate::Body>, Connection<T, crate::Body>)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Builder::new().handshake(io).await
}

// ===== impl SendRequest

impl<B> SendRequest<B> {
    /// Polls to determine whether this sender can be used yet for a request.
    ///
    /// If the associated connection is closed, this returns an Error.
    pub fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<crate::Result<()>> {
        self.dispatch.poll_ready(cx)
    }

    /*
    pub(super) async fn when_ready(self) -> crate::Result<Self> {
        let mut me = Some(self);
        future::poll_fn(move |cx| {
            ready!(me.as_mut().unwrap().poll_ready(cx))?;
            Poll::Ready(Ok(me.take().unwrap()))
        })
        .await
    }

    pub(super) fn is_ready(&self) -> bool {
        self.dispatch.is_ready()
    }

    pub(super) fn is_closed(&self) -> bool {
        self.dispatch.is_closed()
    }
    */
}

impl<B> SendRequest<B>
where
    B: HttpBody + 'static,
{
    /// Sends a `Request` on the associated connection.
    ///
    /// Returns a future that if successful, yields the `Response`.
    ///
    /// # Note
    ///
    /// There are some key differences in what automatic things the `Client`
    /// does for you that will not be done here:
    ///
    /// - `Client` requires absolute-form `Uri`s, since the scheme and
    ///   authority are needed to connect. They aren't required here.
    /// - Since the `Client` requires absolute-form `Uri`s, it can add
    ///   the `Host` header based on it. You must add a `Host` header yourself
    ///   before calling this method.
    /// - Since absolute-form `Uri`s are not required, if received, they will
    ///   be serialized as-is.
    ///
    /// # Example
    ///
    /// ```
    /// # use http::header::HOST;
    /// # use hyper::client::conn::SendRequest;
    /// # use hyper::Body;
    /// use hyper::Request;
    ///
    /// # async fn doc(mut tx: SendRequest<Body>) -> hyper::Result<()> {
    /// // build a Request
    /// let req = Request::builder()
    ///     .uri("/foo/bar")
    ///     .header(HOST, "hyper.rs")
    ///     .body(Body::empty())
    ///     .unwrap();
    ///
    /// // send it and await a Response
    /// let res = tx.send_request(req).await?;
    /// // assert the Response
    /// assert!(res.status().is_success());
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    pub fn send_request(&mut self, req: Request<B>) -> impl Future<Output = crate::Result<Response<Body>>> {
        let sent = self.dispatch.send(req);

        async move {
            match sent {
                Ok(rx) => match rx.await {
                    Ok(Ok(resp)) => Ok(resp),
                    Ok(Err(err)) => Err(err),
                    // this is definite bug if it happens, but it shouldn't happen!
                    Err(_canceled) => panic!("dispatch dropped without returning error"),
                }
                Err(_req) => {
                    tracing::debug!("connection was not ready");

                    Err(crate::Error::new_canceled().with("connection was not ready"))
                }
            }
        }
    }

    /*
    pub(super) fn send_request_retryable(
        &mut self,
        req: Request<B>,
    ) -> impl Future<Output = Result<Response<Body>, (crate::Error, Option<Request<B>>)>> + Unpin
    where
        B: Send,
    {
        match self.dispatch.try_send(req) {
            Ok(rx) => {
                Either::Left(rx.then(move |res| {
                    match res {
                        Ok(Ok(res)) => future::ok(res),
                        Ok(Err(err)) => future::err(err),
                        // this is definite bug if it happens, but it shouldn't happen!
                        Err(_) => panic!("dispatch dropped without returning error"),
                    }
                }))
            }
            Err(req) => {
                tracing::debug!("connection was not ready");
                let err = crate::Error::new_canceled().with("connection was not ready");
                Either::Right(future::err((err, Some(req))))
            }
        }
    }
    */
}

impl<B> fmt::Debug for SendRequest<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendRequest").finish()
    }
}

// ===== impl Connection

impl<T, B> fmt::Debug for Connection<T, B>
where
    T: AsyncRead + AsyncWrite + fmt::Debug + Send + 'static,
    B: HttpBody + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl<T, B> Future for Connection<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.inner.1).poll(cx))? {
            proto::Dispatched::Shutdown => Poll::Ready(Ok(())),
            #[cfg(feature = "http1")]
            proto::Dispatched::Upgrade(_pending) => unreachable!("http2 cannot upgrade"),
        }
    }
}

// ===== impl Builder

impl Builder {
    /// Creates a new connection builder.
    #[inline]
    pub fn new() -> Builder {
        Builder {
            exec: Exec::Default,
            h2_builder: Default::default(),
        }
    }

    /// Provide an executor to execute background HTTP2 tasks.
    pub fn executor<E>(&mut self, exec: E) -> &mut Builder
    where
        E: Executor<BoxSendFuture> + Send + Sync + 'static,
    {
        self.exec = Exec::Executor(Arc::new(exec));
        self
    }

    /// Sets the [`SETTINGS_INITIAL_WINDOW_SIZE`][spec] option for HTTP2
    /// stream-level flow control.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    ///
    /// [spec]: https://http2.github.io/http2-spec/#SETTINGS_INITIAL_WINDOW_SIZE
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_initial_stream_window_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        if let Some(sz) = sz.into() {
            self.h2_builder.adaptive_window = false;
            self.h2_builder.initial_stream_window_size = sz;
        }
        self
    }

    /// Sets the max connection-level flow control for HTTP2
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_initial_connection_window_size(
        &mut self,
        sz: impl Into<Option<u32>>,
    ) -> &mut Self {
        if let Some(sz) = sz.into() {
            self.h2_builder.adaptive_window = false;
            self.h2_builder.initial_conn_window_size = sz;
        }
        self
    }

    /// Sets whether to use an adaptive flow control.
    ///
    /// Enabling this will override the limits set in
    /// `http2_initial_stream_window_size` and
    /// `http2_initial_connection_window_size`.
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_adaptive_window(&mut self, enabled: bool) -> &mut Self {
        use proto::h2::SPEC_WINDOW_SIZE;

        self.h2_builder.adaptive_window = enabled;
        if enabled {
            self.h2_builder.initial_conn_window_size = SPEC_WINDOW_SIZE;
            self.h2_builder.initial_stream_window_size = SPEC_WINDOW_SIZE;
        }
        self
    }

    /// Sets the maximum frame size to use for HTTP2.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_max_frame_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        if let Some(sz) = sz.into() {
            self.h2_builder.max_frame_size = sz;
        }
        self
    }

    /// Sets an interval for HTTP2 Ping frames should be sent to keep a
    /// connection alive.
    ///
    /// Pass `None` to disable HTTP2 keep-alive.
    ///
    /// Default is currently disabled.
    ///
    /// # Cargo Feature
    ///
    /// Requires the `runtime` cargo feature to be enabled.
    #[cfg(feature = "runtime")]
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_keep_alive_interval(
        &mut self,
        interval: impl Into<Option<Duration>>,
    ) -> &mut Self {
        self.h2_builder.keep_alive_interval = interval.into();
        self
    }

    /// Sets a timeout for receiving an acknowledgement of the keep-alive ping.
    ///
    /// If the ping is not acknowledged within the timeout, the connection will
    /// be closed. Does nothing if `http2_keep_alive_interval` is disabled.
    ///
    /// Default is 20 seconds.
    ///
    /// # Cargo Feature
    ///
    /// Requires the `runtime` cargo feature to be enabled.
    #[cfg(feature = "runtime")]
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_keep_alive_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.h2_builder.keep_alive_timeout = timeout;
        self
    }

    /// Sets whether HTTP2 keep-alive should apply while the connection is idle.
    ///
    /// If disabled, keep-alive pings are only sent while there are open
    /// request/responses streams. If enabled, pings are also sent when no
    /// streams are active. Does nothing if `http2_keep_alive_interval` is
    /// disabled.
    ///
    /// Default is `false`.
    ///
    /// # Cargo Feature
    ///
    /// Requires the `runtime` cargo feature to be enabled.
    #[cfg(feature = "runtime")]
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_keep_alive_while_idle(&mut self, enabled: bool) -> &mut Self {
        self.h2_builder.keep_alive_while_idle = enabled;
        self
    }

    /// Sets the maximum number of HTTP2 concurrent locally reset streams.
    ///
    /// See the documentation of [`h2::client::Builder::max_concurrent_reset_streams`] for more
    /// details.
    ///
    /// The default value is determined by the `h2` crate.
    ///
    /// [`h2::client::Builder::max_concurrent_reset_streams`]: https://docs.rs/h2/client/struct.Builder.html#method.max_concurrent_reset_streams
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_max_concurrent_reset_streams(&mut self, max: usize) -> &mut Self {
        self.h2_builder.max_concurrent_reset_streams = Some(max);
        self
    }

    /// Set the maximum write buffer size for each HTTP/2 stream.
    ///
    /// Default is currently 1MB, but may change.
    ///
    /// # Panics
    ///
    /// The value must be no larger than `u32::MAX`.
    #[cfg(feature = "http2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http2")))]
    pub fn http2_max_send_buf_size(&mut self, max: usize) -> &mut Self {
        assert!(max <= std::u32::MAX as usize);
        self.h2_builder.max_send_buffer_size = max;
        self
    }

    /// Constructs a connection with the configured options and IO.
    /// See [`client::conn`](crate::client::conn) for more.
    ///
    /// Note, if [`Connection`] is not `await`-ed, [`SendRequest`] will
    /// do nothing.
    pub fn handshake<T, B>(
        &self,
        io: T,
    ) -> impl Future<Output = crate::Result<(SendRequest<B>, Connection<T, B>)>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: HttpBody + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let opts = self.clone();

        async move {
            tracing::trace!("client handshake HTTP/1");

            let (tx, rx) = dispatch::channel();
            let h2 =
                proto::h2::client::handshake(io, rx, &opts.h2_builder, opts.exec)
                    .await?;
            Ok((
                SendRequest { dispatch: tx },
                Connection { inner: (PhantomData, h2) },
            ))
        }
    }
}

