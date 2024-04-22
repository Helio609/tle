use ntp::formats::timestamp::EPOCH_DELTA;

pub fn current_unix_timestamp() -> Result<u64, String> {
    let address = "ntp.aliyun.com:123";
    let response = ntp::request(address);
    match response {
        Ok(packet) => Ok(packet.transmit_time.sec as u64 - EPOCH_DELTA as u64),
        Err(e) => Err(format!("Error when get unix timestamp from ntp: {:?}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_unix_timestamp() {
        let unix_timestamp = current_unix_timestamp().unwrap();
        println!("Current unix timestamp: {}", unix_timestamp);
    }
}
