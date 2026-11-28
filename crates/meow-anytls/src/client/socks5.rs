//! SOCKS5 protocol implementation for AnyTLS client
//!
//! Implements RFC 1928 SOCKS5 protocol to accept client connections
//! and forward them through AnyTLS Stream

use crate::client::Client;
use crate::util::{AnyTlsError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// SOCKS5 version
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
const AUTH_NO_AUTHENTICATION: u8 = 0x00;
const AUTH_NOT_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 command types
#[allow(dead_code)]
const CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
const CMD_BIND: u8 = 0x02;
#[allow(dead_code)]
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
#[allow(dead_code)]
const REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
#[allow(dead_code)]
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
#[allow(dead_code)]
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
#[allow(dead_code)]
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
#[allow(dead_code)]
const REPLY_TTL_EXPIRED: u8 = 0x06;
#[allow(dead_code)]
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
#[allow(dead_code)]
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 address representation
#[derive(Debug, Clone)]
struct Socks5Addr {
    addr: String,
    port: u16,
}

/// Start SOCKS5 server that accepts connections and forwards them through Client
pub async fn start_socks5_server(listen_addr: &str, client: Arc<Client>) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;

    tracing::info!("[SOCKS5] Listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::debug!("[SOCKS5] New connection from {}", addr);

                let client_clone = Arc::clone(&client);
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_connection(stream, client_clone).await {
                        tracing::error!("[SOCKS5] Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("[SOCKS5] Accept error: {}", e);
            }
        }
    }
}

/// Handle a single SOCKS5 connection
async fn handle_socks5_connection(
    mut client_conn: tokio::net::TcpStream,
    client: Arc<Client>,
) -> Result<()> {
    // Step 1: Authentication negotiation
    tracing::debug!("[SOCKS5] Starting authentication negotiation");
    authenticate(&mut client_conn).await?;
    tracing::debug!("[SOCKS5] Authentication completed");

    // Step 2: Read connection request
    tracing::debug!("[SOCKS5] Reading connection request");
    let (dest_addr, _cmd) = read_connection_request(&mut client_conn).await?;
    tracing::debug!(
        "[SOCKS5] Connection request: {}:{}",
        dest_addr.addr,
        dest_addr.port
    );

    // Step 3: Create proxy connection through AnyTLS
    tracing::debug!(
        "[SOCKS5] Creating proxy stream to {}:{}",
        dest_addr.addr,
        dest_addr.port
    );
    let pooled = match client
        .create_proxy_stream((dest_addr.addr.clone(), dest_addr.port))
        .await
    {
        Ok(pooled) => {
            tracing::debug!(
                "[SOCKS5] Proxy stream created successfully for {}:{}, stream_id={}",
                dest_addr.addr,
                dest_addr.port,
                pooled.id()
            );
            tracing::debug!(
                "[SOCKS5] Session status: closed={}",
                pooled.session().is_closed()
            );
            pooled
        }
        Err(e) => {
            tracing::error!(
                "[SOCKS5] Failed to create proxy stream to {}:{}: {}",
                dest_addr.addr,
                dest_addr.port,
                e
            );
            // Try to provide more helpful error messages
            let error_str = format!("{}", e);
            if error_str.contains("lookup")
                || error_str.contains("DNS")
                || error_str.contains("Try again")
            {
                tracing::error!(
                    "[SOCKS5] DNS resolution failed. Server address may be incorrect or unreachable."
                );
                tracing::error!(
                    "[SOCKS5] Check: 1) Server is running, 2) Server address is correct, 3) Network connectivity"
                );
            }
            send_connection_reply(&mut client_conn, REPLY_GENERAL_FAILURE, dest_addr.clone())
                .await?;
            return Err(e);
        }
    };
    let proxy_stream = Arc::clone(pooled.stream());
    let session = Arc::clone(pooled.session());
    let stream_id = proxy_stream.id();

    // Step 4: Send success reply
    tracing::debug!("[SOCKS5] Sending success reply to client");
    send_connection_reply(&mut client_conn, REPLY_SUCCEEDED, dest_addr.clone()).await?;
    tracing::debug!("[SOCKS5] Success reply sent");

    // Step 5: Bidirectional data forwarding
    tracing::debug!(
        "[SOCKS5] Starting bidirectional data forwarding for stream {}",
        stream_id
    );
    tracing::debug!(
        "[SOCKS5] Session recv_loop should be running: {}",
        !session.is_closed()
    );
    let (mut client_read, mut client_write) = tokio::io::split(client_conn);

    // ===== 新实现：不再需要 Arc<Mutex<>> 包装！=====
    // 直接克隆 Arc<Stream> 用于两个任务
    let proxy_stream_read = Arc::clone(&proxy_stream);
    let session_for_write: Arc<crate::session::Session> = Arc::clone(&session);

    tracing::debug!("[SOCKS5] Spawning Task1 and Task2 for stream {}", stream_id);

    let task1 = tokio::spawn(async move {
        tracing::debug!("[SOCKS5-Task1] Task started for stream {}", stream_id);

        // 获取 reader 的引用（无需锁整个 stream）
        let reader_mutex = proxy_stream_read.reader();
        let mut buf = vec![0u8; 8192];
        let mut iteration = 0u64;

        loop {
            iteration += 1;

            // 获取 reader 的锁并读取
            let n = {
                let mut reader = reader_mutex.lock().await;
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        tracing::debug!(
                            "[SOCKS5-Task1] Proxy stream EOF (stream_id={}, iteration={})",
                            stream_id,
                            iteration
                        );
                        break;
                    }
                    Ok(n) => {
                        tracing::debug!(
                            "[SOCKS5-Task1] Read {} bytes from proxy stream (iteration={})",
                            n,
                            iteration
                        );
                        n
                    }
                    Err(e) => {
                        tracing::error!(
                            "[SOCKS5-Task1] Proxy stream read error: {} (iteration={})",
                            e,
                            iteration
                        );
                        break;
                    }
                }
            }; // reader 锁在这里释放

            // 写入 SOCKS5 客户端（无锁）
            if client_write.write_all(&buf[..n]).await.is_err() {
                tracing::error!(
                    "[SOCKS5-Task1] Client write error (iteration={})",
                    iteration
                );
                break;
            }

            tracing::trace!(
                "[SOCKS5-Task1] Forwarded {} bytes to client (iteration={})",
                n,
                iteration
            );
        }

        tracing::debug!(
            "[SOCKS5-Task1] Task completed for stream {} after {} iterations",
            stream_id,
            iteration
        );
    });

    let task2 = tokio::spawn(async move {
        tracing::debug!(
            "[SOCKS5-Task2] Task spawned, starting client->proxy forwarding for stream {}",
            stream_id
        );
        use bytes::Bytes;
        let mut buf = vec![0u8; 8192];
        let mut iteration = 0u64;

        // Yield to ensure task is actually running
        tokio::task::yield_now().await;

        loop {
            iteration += 1;
            tracing::trace!(
                "[SOCKS5-Task2] Iteration {}: Attempting to read from SOCKS5 client",
                iteration
            );

            let n = match client_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(
                        "[SOCKS5-Task2] SOCKS5 client read EOF (iteration {})",
                        iteration
                    );
                    break;
                }
                Ok(n) => {
                    tracing::debug!(
                        "[SOCKS5-Task2] Read {} bytes from SOCKS5 client (iteration {})",
                        n,
                        iteration
                    );
                    // Log first few bytes for debugging (only in trace mode)
                    if iteration == 1 && n > 0 {
                        let preview_len = std::cmp::min(n, 50);
                        tracing::trace!(
                            "[SOCKS5-Task2] First {} bytes: {:?}",
                            preview_len,
                            &buf[..preview_len]
                        );
                    }
                    n
                }
                Err(e) => {
                    tracing::error!(
                        "[SOCKS5-Task2] Error reading from SOCKS5 client: {} (iteration {})",
                        e,
                        iteration
                    );
                    break;
                }
            };

            // Use session.write_data_frame to send data without unwrapping Arc<Stream>
            tracing::debug!(
                "[SOCKS5-Task2] Writing {} bytes to proxy stream {} via session (iteration {})",
                n,
                stream_id,
                iteration
            );
            match session_for_write
                .write_data_frame(stream_id, Bytes::from(buf[..n].to_vec()))
                .await
            {
                Ok(_) => {
                    tracing::trace!(
                        "[SOCKS5-Task2] Forwarded {} bytes to proxy stream {} (iteration {})",
                        n,
                        stream_id,
                        iteration
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "[SOCKS5-Task2] Error writing {} bytes to proxy stream {}: {} (iteration {})",
                        n,
                        stream_id,
                        e,
                        iteration
                    );
                    break;
                }
            }
        }
        tracing::debug!(
            "[SOCKS5-Task2] Task2 (client->proxy) finished for stream {} after {} iterations",
            stream_id,
            iteration
        );
    });

    tracing::debug!(
        "[SOCKS5] Tasks spawned, waiting for completion (stream {})",
        stream_id
    );
    let (result1, result2) = tokio::join!(task1, task2);
    tracing::debug!("[SOCKS5] Both tasks completed for stream {}", stream_id);
    if let Err(e) = result1 {
        tracing::error!("[SOCKS5] Task1 error: {:?}", e);
    }
    if let Err(e) = result2 {
        tracing::error!("[SOCKS5] Task2 error: {:?}", e);
    }

    tracing::debug!(
        "[SOCKS5] Connection to {}:{} closed",
        dest_addr.addr,
        dest_addr.port
    );
    pooled.close().await;
    Ok(())
}

/// Perform SOCKS5 authentication handshake
async fn authenticate(conn: &mut tokio::net::TcpStream) -> Result<()> {
    // Read client greeting: [VER (1) | NMETHODS (1) | METHODS (NMETHODS)]
    let mut buf = [0u8; 2];
    conn.read_exact(&mut buf).await?;

    let version = buf[0];
    if version != SOCKS5_VERSION {
        return Err(AnyTlsError::Protocol(format!(
            "Unsupported SOCKS version: {}",
            version
        )));
    }

    let nmethods = buf[1] as usize;
    if nmethods == 0 {
        return Err(AnyTlsError::Protocol(
            "No authentication methods provided".to_string(),
        ));
    }

    let mut methods = vec![0u8; nmethods];
    conn.read_exact(&mut methods).await?;

    // Check if NO AUTHENTICATION is supported
    let supports_no_auth = methods.contains(&AUTH_NO_AUTHENTICATION);

    // Send server selection: [VER (1) | METHOD (1)]
    if supports_no_auth {
        conn.write_all(&[SOCKS5_VERSION, AUTH_NO_AUTHENTICATION])
            .await?;
    } else {
        conn.write_all(&[SOCKS5_VERSION, AUTH_NOT_ACCEPTABLE])
            .await?;
        return Err(AnyTlsError::Protocol(
            "Client does not support NO AUTHENTICATION".to_string(),
        ));
    }

    Ok(())
}

/// Read SOCKS5 connection request
/// Returns (destination address, command)
async fn read_connection_request(conn: &mut tokio::net::TcpStream) -> Result<(Socks5Addr, u8)> {
    // Read request header: [VER (1) | CMD (1) | RSV (1) | ATYP (1)]
    let mut header = [0u8; 4];
    conn.read_exact(&mut header).await?;

    let version = header[0];
    if version != SOCKS5_VERSION {
        return Err(AnyTlsError::Protocol(format!(
            "Invalid SOCKS version: {}",
            version
        )));
    }

    let cmd = header[1];
    let _rsv = header[2]; // Reserved, should be 0x00
    let atyp = header[3];

    // Read address based on ATYP
    let addr = match atyp {
        ATYP_IPV4 => {
            let mut ip_buf = [0u8; 4];
            conn.read_exact(&mut ip_buf).await?;
            IpAddr::V4(Ipv4Addr::from(ip_buf)).to_string()
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            conn.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            if domain_len == 0 || domain_len > 255 {
                return Err(AnyTlsError::Protocol("Invalid domain length".to_string()));
            }
            let mut domain_buf = vec![0u8; domain_len];
            conn.read_exact(&mut domain_buf).await?;
            String::from_utf8(domain_buf)
                .map_err(|e| AnyTlsError::Protocol(format!("Invalid domain name: {}", e)))?
        }
        ATYP_IPV6 => {
            let mut ip_buf = [0u8; 16];
            conn.read_exact(&mut ip_buf).await?;
            IpAddr::V6(Ipv6Addr::from(ip_buf)).to_string()
        }
        _ => {
            return Err(AnyTlsError::Protocol(format!(
                "Unsupported address type: 0x{:02x}",
                atyp
            )));
        }
    };

    // Read port (2 bytes, big-endian)
    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok((Socks5Addr { addr, port }, cmd))
}

/// Send SOCKS5 connection reply
async fn send_connection_reply(
    conn: &mut tokio::net::TcpStream,
    reply: u8,
    _addr: Socks5Addr,
) -> Result<()> {
    // Reply format: [VER (1) | REP (1) | RSV (1) | ATYP (1) | BND.ADDR (variable) | BND.PORT (2)]
    // For simplicity, we'll use IPv4 0.0.0.0:0 as bound address
    let reply_buf = vec![
        SOCKS5_VERSION,
        reply,
        0x00, // RSV
        ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00, // BND.ADDR (0.0.0.0)
        0x00,
        0x00, // BND.PORT (0)
    ];

    conn.write_all(&reply_buf).await?;
    conn.flush().await?;

    Ok(())
}
