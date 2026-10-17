// 请求由宿主执行（netcfg 的客户端，DoH / 代理设置与原生代码一致）。
use hostio::http::{Client, ClientBuilder};

pub fn default_client() -> Client {
    Client::new()
}

pub fn default_client_builder() -> ClientBuilder {
    Client::builder()
}
