use std::net::SocketAddr;

use hyper;


macro_rules! server_addrs {
    ($( ([$ip1:tt, $ip2:tt, $ip3:tt, $ip4:tt], $port:tt), )+) => {
        server_addrs!(@iter
            [$(([$ip1, $ip2, $ip3, $ip4], $port),)+]
            [0]
            []
        );
    };

    (@iter
        []
        [$($len:tt)+]
        [$(([$ip1:tt, $ip2:tt, $ip3:tt, $ip4:tt], $port:tt),)+]
    ) => {
        lazy_static! {
            pub static ref TCP_SERVER_ADDRS: [SocketAddr; $($len)+] = [
                $(([$ip1, $ip2, $ip3, $ip4], $port).into(),)+
            ];

            pub static ref HTTP_SERVER_ADDRS: [hyper::Uri; $($len)+] = [
                $(
                    concat!("http://", $ip1, ".", $ip2, ".", $ip3, ".", $ip4, ":", $port, "/api")
                        .parse().unwrap(),
                )+
            ];
        }
    };

    (@iter
        [([$ip1:tt, $ip2:tt, $ip3:tt, $ip4:tt], $port:tt), $($ip_in:tt)*]
        [$($len:tt)+]
        [$($ip_out:tt)*]
    ) => {
        server_addrs!(@iter
            [$($ip_in)*]
            [$($len)+ + 1]
            [$($ip_out)* ([$ip1, $ip2, $ip3, $ip4], $port),]
        );
    };
}

server_addrs! {
    ([149, 154, 167, 51], 443),
}
