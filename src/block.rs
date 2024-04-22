#[derive(Debug)]
pub struct Block {
    pub part_id: u8,
    pub md5: String,
    pub part_aes: Vec<u8>,
    pub time: Option<String>
}

impl Block {
    pub fn new(part_id: u8, md5: &String, part_aes: &Vec<u8>, time: Option<String>) -> Self {
        Block {
            part_id,
            md5: md5.clone(),
            part_aes: part_aes.clone(),
            time: time
        }
    }
}
