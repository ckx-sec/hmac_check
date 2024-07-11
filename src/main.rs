use std::{collections::HashMap, fs::File};

use numeric_array::{
    generic_array::{ConstArrayLength, GenericArray},
    narr, NumericArray,
};
use rand::{distributions::Alphanumeric, Rng};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
//use sha2::{Digest, Sha256};
use std::io::{self, Write};
use sha1::{Digest, Sha1};
use hmac::{Hmac, Mac};

fn generate_random_message(length: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect()
}

fn generate_similar_message(message: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut message_list = message.to_vec();
    let idx = rng.gen_range(0..message.len());
    let original_char = message[idx];
    let mut new_char = original_char;
    while new_char == original_char {
        new_char = rng.sample(Alphanumeric) as u8;
    }
    message_list[idx] = new_char;
    message_list
}

fn bit_diff(a: u8, b: u8) -> i32 {
    (a ^ b).count_ones() as i32
}

fn main() {
    println!("Hello, world!");

    let message_length = 101;
    let num_message_pairs = 10000;
    let message_pairs_file = "hmac_message_pairs.txt";
    let mut message_pairs = Vec::new();
    let mut f = File::create(message_pairs_file).unwrap();

    for _ in 0..num_message_pairs {
        let message1 = generate_random_message(message_length);
        let message2 = generate_similar_message(&message1);
        message_pairs.push((message1.clone(), message2.clone()));
        writeln!(f, "Message1: {:x?}, Message2: {:x?}", message1, message2).unwrap();
    }

    const BLOCK_SIZE: usize = 64;

    let key_str = b"some_secret_keys";
    let mut key = [0u8; BLOCK_SIZE];
    key[0..key_str.len()].copy_from_slice(key_str);
    let pads = (0u8..=255)
        .flat_map(|o| (0u8..=255).map(move |i| (o, i)))
        .collect::<Vec<_>>();
    // let result_map = pads
    //     .par_iter()
    //     .map(|(opad_val, ipad_val)| {
    //         let diff_list = message_pairs
    //             .par_iter()
    //             .map(|(msg1, msg2)| {
    //                 let hmac1 = hmac(&key, *opad_val, *ipad_val, msg1);
    //                 let hmac2 = hmac(&key, *opad_val, *ipad_val, msg2);
    //                 let mut diff = 0;
    //                 for i in 0..hmac1.len() {
    //                     if hmac1[i] != hmac2[1] {
    //                         diff += 1;
    //                     }
    //                 }
    //                 diff
    //             })
    //             .collect::<Vec<_>>();
    //         let mut inner_map: HashMap<i32, i32> = HashMap::new();
    //         for diff in diff_list {
    //             if let Some(count) = inner_map.get_mut(&diff) {
    //                 *count += 1;
    //             } else {
    //                 inner_map.insert(diff, 0);
    //             }
    //         }
    //         (opad_val, ipad_val, inner_map)
    //     })
    //     .collect::<Vec<_>>();
    // println!("compute complete");

    let result_map = pads
        .par_iter()
        .map(|(opad_val, ipad_val)| {
            let diff_list = message_pairs
                .par_iter()
                .map(|(msg1, msg2)| {
                    let hmac1 = hmac(&key, *opad_val, *ipad_val, msg1);
                    let hmac2 = hmac(&key, *opad_val, *ipad_val, msg2);
                    let mut diff = 0;
                    for (byte1, byte2) in hmac1.iter().zip(hmac2.iter()) {
                        diff += bit_diff(*byte1, *byte2);
                    }
                    diff
                })
                .collect::<Vec<_>>();
            let mut inner_map: HashMap<i32, i32> = HashMap::new();
            for diff in diff_list {
                *inner_map.entry(diff).or_insert(0) += 1;
            }
            (opad_val, ipad_val, inner_map)
        })
        .collect::<Vec<_>>();

    println!("compute complete");

    let output_file = "hmac_differences_results.txt";
    let mut f = File::create(output_file).unwrap();
    for (opad_val, ipad_val, diff_map) in result_map {
        writeln!(f, "opad: {:#x}, ipad: {:#x}", opad_val, ipad_val).unwrap();
        for (diff, count) in diff_map {
            writeln!(f, "  Difference: {} characters, Count: {}", diff, count).unwrap();
        }
        writeln!(f).unwrap();
    }

    println!("Results written to {}", output_file);
    println!("Message pairs written to {}", message_pairs_file);


 

    let result_map = pads.par_iter().map(|(opad_val, ipad_val)| {
        let entropies = message_pairs.par_iter().map(|(msg1, _)| {
            let hmac_output =hmac(&key, *opad_val, *ipad_val, msg1);
            calculate_entropy(&hmac_output)
        }).collect::<Vec<_>>();
        let avg_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;
        (opad_val, ipad_val, avg_entropy)
    }).collect::<Vec<_>>();

    let output_file = "hmac_entropy_results.txt";
    let mut f = File::create(output_file).unwrap();
    for (opad_val, ipad_val, entropy) in result_map {
        writeln!(f, "opad: {:#x}, ipad: {:#x}, Entropy: {}", opad_val, ipad_val, entropy).unwrap();
    }
    println!("Results written to {}", output_file);

    // Specific check for opad = 0x36 and ipad = 0x5c using official HMAC library
    // let opad_val = 0x5c;
    // let ipad_val = 0x36;
    // for (msg1, msg2) in message_pairs.iter() {
    //     let custom_hmac1 = hmac(&key, opad_val, ipad_val, msg1);
    //     let custom_hmac2 = hmac(&key, opad_val, ipad_val, msg2);

    //     type HmacSha1 = Hmac<Sha1>;
    //     let mut mac1 = HmacSha1::new_from_slice(&key).expect("HMAC can take key of any size");
    //     mac1.update(msg1);
    //     let result1 = mac1.finalize();
    //     let official_hmac1 = result1.into_bytes().to_vec();

    //     let mut mac2 = HmacSha1::new_from_slice(&key).expect("HMAC can take key of any size");
    //     mac2.update(msg2);
    //     let result2 = mac2.finalize();
    //     let official_hmac2 = result2.into_bytes().to_vec();

    //     println!(
    //         "Custom HMAC1: {:x?}, Official HMAC1: {:x?}, Equal: {}",
    //         custom_hmac1, official_hmac1, custom_hmac1 == official_hmac1
    //     );
    //     println!(
    //         "Custom HMAC2: {:x?}, Official HMAC2: {:x?}, Equal: {}",
    //         custom_hmac2, official_hmac2, custom_hmac2 == official_hmac2
    //     );
    // }
}


fn hmac(key: &[u8], opad_val: u8, ipad_val: u8, message: &[u8]) -> Vec<u8> {
    // Ensure the key is the right length
    let mut key_block = [0x00; 64];
    if key.len() > 64 {
        let mut hasher = Sha1::new();
        hasher.update(key);
        let hashed_key = hasher.finalize();
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // println!("opad_val: {:#x}, ipad_val: {:#x}", opad_val, ipad_val);
    let mut opad = [opad_val; 64];
    let mut ipad = [ipad_val; 64];
    for i in 0..64 {
        opad[i] ^= key_block[i];
        ipad[i] ^= key_block[i];
    }

    let mut hasher = Sha1::new();
    hasher.update(&ipad);
    hasher.update(message);
    let inner_hash = hasher.finalize();

    let mut hasher = Sha1::new();
    hasher.update(&opad);
    hasher.update(&inner_hash);
    hasher.finalize().to_vec()
}

// fn calculate_entropy(data: &Vec<u8>) -> f64 {
//     let mut counts = HashMap::new();
//     let total = data.len() as f64;

//     for byte in data.iter() {
//         *counts.entry(*byte).or_insert(0) += 1;
//     }

//     counts.values().fold(0.0, |entropy, &count| {
//         let probability = count as f64 / total;
//         entropy - probability * probability.log2()
//     })
// }

fn calculate_entropy(data: &Vec<u8>) -> f64 {
    let mut bit_counts = HashMap::new();
    let total_bits = (data.len() * 8) as f64; 

    for byte in data.iter() {
        for bit_index in 0..8 {
            let bit = (byte >> bit_index) & 1; 
            *bit_counts.entry(bit).or_insert(0) += 1;
        }
    }

    bit_counts.values().fold(0.0, |entropy, &count| {
        let probability = count as f64 / total_bits;
        entropy - probability * probability.log2()
    })
}