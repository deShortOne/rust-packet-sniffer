pub fn join_nums(nums: &[u8], sep: &str) -> String {
    let str_nums: Vec<String> = nums.iter().map(|n| n.to_string()).collect();
    str_nums.join(sep)
}

pub fn convert_binary_to_decimal(nums: &[u8]) -> usize {
    // could also do bitwise notation but (payload[20] as usize) << 8 | (payload[21] as usize) but easy to screw up
    let str_nums: Vec<String> = nums.iter().map(|n| format!("{:0>8b}", n)).collect();
    let str_nums = str_nums.join("");
    usize::from_str_radix(&str_nums, 2).unwrap()
}
