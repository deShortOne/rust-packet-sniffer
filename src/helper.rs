pub fn join_nums(nums: &[u8], sep: &str) -> String {
    let str_nums: Vec<String> = nums.iter().map(|n| n.to_string()).collect();
    str_nums.join(sep)
}
