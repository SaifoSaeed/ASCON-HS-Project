use std::fs::OpenOptions;
use std::fs::File;
use std::io::Write;
use rand::Rng;
use std::mem;
use std::env;

fn rotr(x: u64, i: u64) -> u64 {
    let x = (x >> i)^(x<<(64-i));
    return x;
}

/*fn print_state(x: &[u64; 5]) {
    for i in 0..5 {
        println!("{:016x}", x[i])
    }
    println!("");
}

fn print_arr(arr: &[u64; 4], ct: *const u64, pt: *const u64, new_pt: *const u64){
    // println!("arr:\t{:?}", arr.as_ptr());
    // println!("ct:\t{:?}", ct);
    // println!("pt:\t{:?}", pt);
    // println!("new_pt:\t{:?}", new_pt);

    if arr.as_ptr() == ct {
        print!("Ciphertext: ");
    }

    else if arr.as_ptr() == pt {
        print!("Input Plaintext: ");
    }

    else  if arr.as_ptr() == new_pt {
        print!("Decrypted Plaintext: ");
    }
    print!("\n");
    for i in 0..arr.len() { print!("{:016x} ", arr[i]); }
    print!("\n\n");
}
*/

fn p(x: &mut [u64; 5], i:u64, rnd: u64) {
    
    let constants: [u64; 16] = [ 0x000000000000003c, 0x000000000000002d, 0x000000000000001e,
    0x000000000000000f, 0x00000000000000f0, 0x00000000000000e1, 0x00000000000000d2,
    0x00000000000000c3, 0x00000000000000b4, 0x00000000000000a5, 0x0000000000000096,
    0x0000000000000087, 0x0000000000000078, 0x0000000000000069, 0x000000000000005a, 0x000000000000004b ];

    let index: usize = (16 - rnd + i) as usize;

    x[2] ^= constants[index];

    let mut t: [u64; 5] = [0; 5];

    x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
    t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
    t[0] = !t[0]; t[1] = !t[1]; t[2] = !t[2]; t[3] = !t[3]; t[4] = !t[4];
    t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
    x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = !x[2];

    x[0] = x[0] ^ rotr(x[0], 19) ^ rotr(x[0], 28);
    x[1] = x[1] ^ rotr(x[1], 61) ^ rotr(x[1], 39);
    x[2] = x[2] ^ rotr(x[2], 1)  ^ rotr(x[2], 6);
    x[3] = x[3] ^ rotr(x[3], 10) ^ rotr(x[3], 17);
    x[4] = x[4] ^ rotr(x[4], 7)  ^ rotr(x[4], 41);
    
}

fn init(x: &mut [u64; 5], iv: u64, key: [u64; 2], nonce: [u64; 2]) {
    x[0] = iv;
    x[1] = key[0];
    x[2] = key[1];
    x[3] = nonce[0];
    x[4] = nonce[1];
    
    for i in 0..12 {
        p(x, i, 12);
    }

    x[3] ^= key[0];
    x[4] ^= key[1];
}

fn encrypt(x: &mut [u64; 5], pt: [u64; 4], ct: &mut [u64; 4]) {
    x[4] ^= 0x8000000000000000;
    for i in 0..mem::size_of_val(&pt)/16 {
        x[0] ^= pt[2*i];
        x[1] ^= pt[2*i + 1];
        ct[2*i] = x[0];
        ct[2*i + 1] = x[1];

        for j in 0..8 { p(x, j, 8); }
    }
    x[0] ^= 1;
}

fn finalize(x: &mut [u64; 5], key: [u64; 2], tag: &mut [u64; 2]) {
    x[2] ^= key[0];
    x[3] ^= key[1];
    for i in 0..12 { p(x, i, 12); }
    tag[0] = x[3] ^ key[0];
    tag[1] = x[4] ^ key[1];
}

fn decrypt(x: &mut [u64; 5], ct: &[u64; 4], pt: &mut [u64; 4]) {
    x[4] ^= 0x8000000000000000;
    for i in 0..mem::size_of_val(ct)/16 {

        pt[2*i] = x[0] ^ ct[2*i];
        pt[2*i + 1] = x[1] ^ ct[2*i + 1];

        x[0] = ct[2*i];
        x[1] = ct[2*i + 1];

        for j in 0..8 { 
            p(x, j, 8); 
        }
    }
    x[0] ^= 1;
}

fn format_hex(arr: &[u64]) -> String {
    arr.iter().map(|&val| format!("{:016x}", val)).collect::<Vec<_>>().join(" ")
}

fn main() {

    let args: Vec<String> = env::args().collect();
    
    let mut rng = rand::thread_rng();

    let mut x: [u64; 5] = [0; 5];
    let iv: u64 = 0x00001000808c0001;
    let key: [u64; 2] = [rng.gen_range(0..u64::MAX), rng.gen_range(0..u64::MAX)];
    let nonce: [u64; 2] = [0;2];
    
    let mut pt: [u64; 4] = [0; 4];
    rng.fill(&mut pt);

    let mut ct: [u64; 4] = [0; 4];
    let mut tag: [u64; 2] = [0; 2];
    let mut dec_pt: [u64; 4] = [0; 4];

    init(&mut x, iv, key, nonce);
    encrypt(&mut x, pt, &mut ct);
    finalize(&mut x, key, &mut tag);

    init(&mut x, iv, key, nonce);
    decrypt(&mut x, &ct, &mut dec_pt);

    let mut perm_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("perm_vectors.txt")
        .expect("Failed to create perm_vectors.txt");

    let mut file = File::create("vectors.txt").expect("Failed to create vectors.txt");
    
    writeln!(file, "IV: {:016x}", iv).unwrap();
    writeln!(file, "KEY: {}", format_hex(&key)).unwrap();
    writeln!(file, "NONCE: {}", format_hex(&nonce)).unwrap();
    writeln!(file, "CT: {}", format_hex(&ct)).unwrap();
    writeln!(file, "TAG: {}", format_hex(&tag)).unwrap();
    writeln!(file, "PT: \t{}", format_hex(&pt)).unwrap();
    writeln!(file, "DEC_PT: {}", format_hex(&dec_pt)).unwrap();

    if args.len() > 1 {
        writeln!(perm_file, "V{}\t\t: ({}{}{},{}{})", args[1], format_hex(&dec_pt), format_hex(&key), format_hex(&nonce), format_hex(&ct), format_hex(&tag)).unwrap();
    }

    println!("Successfully generated vectors.txt");
}