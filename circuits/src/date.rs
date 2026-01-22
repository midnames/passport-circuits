pub struct Date {
    pub day: u8,
    pub month: u8,
    pub year: u16,
}

impl From<Date> for [u8; 10] {
    fn from(value: Date) -> Self {
        let mut buf = [0u8; 10];
        let s = format!("{:04}-{:02}-{:02}", value.year, value.month, value.day);
        buf.copy_from_slice(s.as_bytes());
        buf
    }
}
