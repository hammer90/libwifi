pub fn get_bit(data: &[u8], bit_num: usize) -> bool {
    let byte_num = bit_num / 8;
    let bit_num = bit_num % 8;
    if byte_num >= data.len() {
        return false;
    }
    let byte = data[byte_num];
    byte & (1 << bit_num) > 0
}

pub fn get_bits(data: &[u8], start_bit: usize, end_bit: usize) -> u8 {
    let mut res = 0;

    for bit_index in start_bit..end_bit {
        let bit_value = get_bit(data, bit_index);
        if bit_value {
            res += 1 << (bit_index - start_bit);
        }
    }

    res
}

#[cfg(test)]
mod test_get_bit {
    use super::*;

    #[test]
    fn get_from_single_byte() {
        let data = [1 << 3];

        assert_eq!(get_bit(&data, 2), false);
        assert_eq!(get_bit(&data, 3), true);
        assert_eq!(get_bit(&data, 4), false);
    }

    #[test]
    fn beyond_single_byte() {
        let data = [0xFF];

        assert_eq!(get_bit(&data, 8), false);
        assert_eq!(get_bit(&data, 9), false);
    }

    #[test]
    fn get_from_second_byte() {
        let data = [0, 1 << 3];

        assert_eq!(get_bit(&data, 10), false);
        assert_eq!(get_bit(&data, 11), true);
        assert_eq!(get_bit(&data, 12), false);
    }
}

#[cfg(test)]
mod test_get_bits {
    use bitvec::{order::Lsb0, prelude::*, vec::BitVec};

    use super::*;

    #[test]
    fn get_from_single_bytes() {
        let data = [1 << 3];
        let b = BitVec::<_, Lsb0>::from_slice(&data);

        assert_eq!(get_bits(&data, 1, 3), b[1..3].load());
        assert_eq!(get_bits(&data, 2, 4), b[2..4].load());
        assert_eq!(get_bits(&data, 3, 5), b[3..5].load());
    }

    #[test]
    fn beyond_single_byte() {
        let data = [0xFF];

        assert_eq!(get_bits(&data, 8, 10), 0);
    }

    #[test]
    fn get_from_second_byte() {
        let data = [0, 1 << 3];
        let b = BitVec::<_, Lsb0>::from_slice(&data);

        assert_eq!(get_bits(&data, 9, 11), b[9..11].load());
        assert_eq!(get_bits(&data, 10, 12), b[10..12].load());
        assert_eq!(get_bits(&data, 11, 13), b[11..13].load());
    }
}
