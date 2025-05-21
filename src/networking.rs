use std::net::IpAddr;
use local_ip_address::list_afinet_netifas;
use tracing::info;

pub fn generate_connection_urls(
    ip_addr: IpAddr,
    port: u16,
    use_tls: bool,
) -> Vec<String> {
    let protocol = if use_tls { "https" } else { "http" };
    
    match ip_addr {
        IpAddr::V4(ip) if ip.is_loopback() => {
            vec![format!("{}://127.0.0.1:{}/", protocol, port)]
        }
        IpAddr::V6(ip) if ip.is_loopback() => {
            vec![format!("{}://[::1]:{}/", protocol, port)]
        }
        IpAddr::V4(ip) if ip.is_unspecified() => {
            let mut urls = vec![
                format!("{}://127.0.0.1:{}/", protocol, port),
                format!("{}://[::1]:{}/", protocol, port)
            ];
            if let Ok(netifs) = list_afinet_netifas() {
                for (ifname, ip) in netifs {
                    match ip {
                        IpAddr::V4(ipv4) if !ipv4.is_loopback() => {
                            urls.push(format!("{}://{}:{}/", protocol, ipv4, port));
                        }
                        IpAddr::V6(ipv6) if !ipv6.is_loopback() => {
                            let url = if ipv6.is_unicast_link_local() {
                                format!("{}://[{}%{}]:{}/", protocol, ipv6, ifname, port)
                            } else {
                                format!("{}://[{}]:{}/", protocol, ipv6, port)
                            };
                            urls.push(url);
                        }
                        _ => (),
                    }
                }
            }
            urls
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            let mut urls = vec![
                format!("{}://127.0.0.1:{}/", protocol, port),
                format!("{}://[::1]:{}/", protocol, port)
            ];
            if let Ok(netifs) = list_afinet_netifas() {
                for (ifname, ip) in netifs {
                    if let IpAddr::V6(ipv6) = ip {
                        if !ipv6.is_loopback() {
                            let url = if ipv6.is_unicast_link_local() {
                                format!("{}://[{}%{}]:{}/", protocol, ipv6, ifname, port)
                            } else {
                                format!("{}://[{}]:{}/", protocol, ipv6, port)
                            };
                            urls.push(url);
                        }
                    }
                }
            }
            urls
        }
        IpAddr::V6(ip) => vec![format!("{}://[{}]:{}/", protocol, ip, port)],
        _ => vec![format!("{}://{}:{}/", protocol, ip_addr, port)],
    }
}

pub fn log_connection_urls(urls: &[String]) {
    info!("Server available at:");
    for url in urls {
        if url.contains("[fe80::") {
            info!("- {} (link-local IPv6 - may not be accessible from browsers)", url);
        } else {
            info!("- {}", url);
        }
    }
    info!("Note: Link-local IPv6 addresses (fe80::) may not be accessible from browsers directly");
}
