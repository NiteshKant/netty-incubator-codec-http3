/*
 * Copyright 2020 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.incubator.codec.http3.example;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollChannelOption;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollMode;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.incubator.codec.http3.DefaultHttp3DataFrame;
import io.netty.incubator.codec.http3.DefaultHttp3HeadersFrame;
import io.netty.incubator.codec.http3.Http3;
import io.netty.incubator.codec.http3.Http3DataFrame;
import io.netty.incubator.codec.http3.Http3FrameToHttpObjectCodec;
import io.netty.incubator.codec.http3.Http3HeadersFrame;
import io.netty.incubator.codec.http3.Http3RequestStreamInboundHandler;
import io.netty.incubator.codec.http3.Http3ServerConnectionHandler;
import io.netty.incubator.codec.quic.InsecureQuicTokenHandler;
import io.netty.incubator.codec.quic.Quic;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import io.netty.incubator.codec.quic.QuicStreamChannel;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.ResourceLeakDetector;
import io.netty.util.internal.logging.InternalLogLevel;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import static io.netty.handler.codec.http.HttpResponseStatus.OK;

public final class Http3ServerExample {
    private static final ByteBuf CONTENT = Unpooled.directBuffer().writeZero(16 * 1024);
    private Http3ServerExample() { }

    public static void main(String... args) throws Exception {
        System.setProperty("io.netty.native.deleteLibAfterLoading", "false");
        InternalLoggerFactory.setDefaultFactory(new InternalLoggerFactory() {
            @Override
            protected InternalLogger newInstance(String name) {
                return new InternalLogger() {
                    @Override
                    public String name() {
                        return name;
                    }

                    @Override
                    public boolean isTraceEnabled() {
                        return false;
                    }

                    @Override
                    public void trace(String msg) {
                        // NOOP
                    }

                    @Override
                    public void trace(String format, Object arg) {
                        // NOOP
                    }

                    @Override
                    public void trace(String format, Object argA, Object argB) {
                        // NOOP
                    }

                    @Override
                    public void trace(String format, Object... arguments) {
                        // NOOP
                    }

                    @Override
                    public void trace(String msg, Throwable t) {
                        // NOOP
                    }

                    @Override
                    public void trace(Throwable t) {
                        // NOOP
                    }

                    @Override
                    public boolean isDebugEnabled() {
                        return false;
                    }

                    @Override
                    public void debug(String msg) {
                        // NOOP
                    }

                    @Override
                    public void debug(String format, Object arg) {
                        // NOOP
                    }

                    @Override
                    public void debug(String format, Object argA, Object argB) {
                        // NOOP
                    }

                    @Override
                    public void debug(String format, Object... arguments) {
                        // NOOP
                    }

                    @Override
                    public void debug(String msg, Throwable t) {
                        // NOOP
                    }

                    @Override
                    public void debug(Throwable t) {
                        // NOOP
                    }

                    @Override
                    public boolean isInfoEnabled() {
                        return false;
                    }

                    @Override
                    public void info(String msg) {
                        // NOOP
                    }

                    @Override
                    public void info(String format, Object arg) {
                        // NOOP
                    }

                    @Override
                    public void info(String format, Object argA, Object argB) {
                        // NOOP
                    }

                    @Override
                    public void info(String format, Object... arguments) {
                        // NOOP
                    }

                    @Override
                    public void info(String msg, Throwable t) {
                        // NOOP
                    }

                    @Override
                    public void info(Throwable t) {
                        // NOOP
                    }

                    @Override
                    public boolean isWarnEnabled() {
                        return false;
                    }

                    @Override
                    public void warn(String msg) {
                        // NOOP
                    }

                    @Override
                    public void warn(String format, Object arg) {
                        // NOOP
                    }

                    @Override
                    public void warn(String format, Object... arguments) {
                        // NOOP
                    }

                    @Override
                    public void warn(String format, Object argA, Object argB) {
                        // NOOP
                    }

                    @Override
                    public void warn(String msg, Throwable t) {
                        // NOOP
                    }

                    @Override
                    public void warn(Throwable t) {
                        // NOOP
                    }

                    @Override
                    public boolean isErrorEnabled() {
                        return false;
                    }

                    @Override
                    public void error(String msg) {
                        // NOOP
                    }

                    @Override
                    public void error(String format, Object arg) {
                        // NOOP
                    }

                    @Override
                    public void error(String format, Object argA, Object argB) {
                        // NOOP
                    }

                    @Override
                    public void error(String format, Object... arguments) {
                        // NOOP
                    }

                    @Override
                    public void error(String msg, Throwable t) {
                        // NOOP
                    }

                    @Override
                    public void error(Throwable t) {
                        // NOOP
                    }

                    @Override
                    public boolean isEnabled(InternalLogLevel level) {
                        return false;
                    }

                    @Override
                    public void log(InternalLogLevel level, String msg) {
                        // NOOP
                    }

                    @Override
                    public void log(InternalLogLevel level, String format, Object arg) {
                        // NOOP
                    }

                    @Override
                    public void log(InternalLogLevel level, String format, Object argA, Object argB) {
                        // NOOP
                    }

                    @Override
                    public void log(InternalLogLevel level, String format, Object... arguments) {
                        // NOOP
                    }

                    @Override
                    public void log(InternalLogLevel level, String msg, Throwable t) {
                        // NOOP
                    }

                    @Override
                    public void log(InternalLogLevel level, Throwable t) {
                        // NOOP
                    }
                };
            }
        });

        class Http3RequestHandler extends Http3RequestStreamInboundHandler {

            @Override
            public void channelActive(ChannelHandlerContext ctx) throws Exception {
                super.channelActive(ctx);
            }

            @Override
            protected void channelRead(ChannelHandlerContext ctx,
                                       Http3HeadersFrame frame, boolean isLast) {
                if (isLast) {
                    writeResponse(ctx);
                }

                ReferenceCountUtil.release(frame);
            }

            @Override
            protected void channelRead(ChannelHandlerContext ctx,
                                       Http3DataFrame frame, boolean isLast) {
                if (isLast) {
                    writeResponse(ctx);
                }
                ReferenceCountUtil.release(frame);
            }

            private int numBytes =  100 * 1024 * 1024;

            private void writeResponse(ChannelHandlerContext ctx) {
                Http3HeadersFrame headersFrame = new DefaultHttp3HeadersFrame();
                headersFrame.headers().status(OK.codeAsText());
                //headersFrame.headers().addInt("content-length", CONTENT.length);
                ctx.write(headersFrame);
                writeData(ctx);
            }

            @Override
            public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
                if (ctx.channel().isWritable()) {
                    writeData(ctx);
                }
                super.channelWritabilityChanged(ctx);
            }

            private void writeData(ChannelHandlerContext ctx) {
                if (numBytes > 0) {
                    ChannelFuture future;
                    do {
                        future = ctx.writeAndFlush(new DefaultHttp3DataFrame(CONTENT.retainedDuplicate()));
                        numBytes -= CONTENT.readableBytes();
                    } while (numBytes > 0 && ctx.channel().isWritable());
                    if (numBytes <=0 ) {
                        future.addListener(QuicStreamChannel.WRITE_FIN);
                    }
                }
            }
        };

        class Http1RequestHandler extends ChannelInboundHandlerAdapter {
            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                if (msg instanceof LastHttpContent) {
                    FullHttpResponse response = new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1, OK, CONTENT.retainedDuplicate());
                    response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, CONTENT.readableBytes());
                    ctx.writeAndFlush(response);
                }
            }
        }

        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);
        SelfSignedCertificate cert = new SelfSignedCertificate();
        QuicSslContext sslContext = QuicSslContextBuilder.forServer(cert.key(), null, cert.cert())
                .applicationProtocols(Http3.supportedApplicationProtocols()).earlyData(true).build();
        ChannelHandler codec = Http3.newQuicServerCodecBuilder()
                .sslContext(sslContext)
                .maxIdleTimeout(5000, TimeUnit.MILLISECONDS)
                .maxSendUdpPayloadSize(1500)
                .maxRecvUdpPayloadSize(1500)
                .initialMaxData(10000000)
                .initialMaxStreamDataBidirectionalLocal(1000000)
                .initialMaxStreamDataBidirectionalRemote(1000000)
                .initialMaxStreamsBidirectional(100000)
                .tokenHandler(InsecureQuicTokenHandler.INSTANCE)
                .handler(new ChannelInitializer<QuicChannel>() {
                    @Override
                    protected void initChannel(QuicChannel ch) {
                        ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                                System.err.println("INACTIVE");
                                ((QuicChannel) ctx.channel()).collectStats().addListener(f -> {
                                    System.err.println(f.getNow());
                                });
                            }
                        });
                        ch.pipeline().addLast(new Http3ServerConnectionHandler(
                                new ChannelInitializer<QuicStreamChannel>() {
                                    // Called for each request-stream,
                                    @Override
                                    protected void initChannel(QuicStreamChannel ch) {
                                        ch.pipeline().addLast(new Http3RequestHandler());
                                        //
                                        //
                                        // ch.pipeline().addLast(new Http3FrameToHttpObjectCodec(true));
                                        //ch.pipeline().addLast(new Http1RequestHandler());
                                    }
                                }));
                    }
                }).build();

        EventLoopGroup group = null;
        try {
            Bootstrap bs = new Bootstrap();
            final Class<? extends DatagramChannel> channelClass;
            if (Epoll.isAvailable()) {
                group = new EpollEventLoopGroup(1);
                channelClass = EpollDatagramChannel.class;
                // recvmmsg should be used

                bs.option(EpollChannelOption.MAX_DATAGRAM_PAYLOAD_SIZE, 1500)
                        .option(ChannelOption.RCVBUF_ALLOCATOR, new FixedRecvByteBufAllocator(  32 * 1024));


                //bs.option(EpollChannelOption.UDP_GRO, true)
                //        .option(ChannelOption.RCVBUF_ALLOCATOR, new FixedRecvByteBufAllocator( 32 * 1024));
            } else {
                group = new NioEventLoopGroup(1);
                channelClass = NioDatagramChannel.class;
            }
            Channel channel = bs.group(group)
                    .channel(channelClass)
                    .handler(new ChannelInitializer<DatagramChannel>() {
                        @Override
                        protected void initChannel(DatagramChannel datagramChannel) throws Exception {
                            datagramChannel.pipeline().addLast(codec);
                        }
                    })
                    //.option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(8 * 1024, 16 * 1024))
                    .bind(new InetSocketAddress(8888)).sync().channel();
            channel.closeFuture().sync();
        } finally {
            if (group != null) {
                group.shutdownGracefully();
            }
        }
    }
}
