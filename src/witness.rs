use circom_prover::graph;

pub fn dispatch_witness(depth: u16) -> fn(&str) -> anyhow::Result<Vec<u8>> {
    match depth {
        1_u16 => {
            graph!(semaphore1, "../witness_graph/semaphore-1.bin");
            semaphore1_witness
        }
        2_u16 => {
            graph!(semaphore2, "../witness_graph/semaphore-2.bin");
            semaphore2_witness
        }
        3_u16 => {
            graph!(semaphore3, "../witness_graph/semaphore-3.bin");
            semaphore3_witness
        }
        4_u16 => {
            graph!(semaphore4, "../witness_graph/semaphore-4.bin");
            semaphore4_witness
        }
        5_u16 => {
            graph!(semaphore5, "../witness_graph/semaphore-5.bin");
            semaphore5_witness
        }
        6_u16 => {
            graph!(semaphore6, "../witness_graph/semaphore-6.bin");
            semaphore6_witness
        }
        7_u16 => {
            graph!(semaphore7, "../witness_graph/semaphore-7.bin");
            semaphore7_witness
        }
        8_u16 => {
            graph!(semaphore8, "../witness_graph/semaphore-8.bin");
            semaphore8_witness
        }
        9_u16 => {
            graph!(semaphore9, "../witness_graph/semaphore-9.bin");
            semaphore9_witness
        }
        10_u16 => {
            graph!(semaphore10, "../witness_graph/semaphore-10.bin");
            semaphore10_witness
        }
        11_u16 => {
            graph!(semaphore11, "../witness_graph/semaphore-11.bin");
            semaphore11_witness
        }
        12_u16 => {
            graph!(semaphore12, "../witness_graph/semaphore-12.bin");
            semaphore12_witness
        }
        13_u16 => {
            graph!(semaphore13, "../witness_graph/semaphore-13.bin");
            semaphore13_witness
        }
        14_u16 => {
            graph!(semaphore14, "../witness_graph/semaphore-14.bin");
            semaphore14_witness
        }
        15_u16 => {
            graph!(semaphore15, "../witness_graph/semaphore-15.bin");
            semaphore15_witness
        }
        16_u16 => {
            graph!(semaphore16, "../witness_graph/semaphore-16.bin");
            semaphore16_witness
        }
        17_u16 => {
            graph!(semaphore17, "../witness_graph/semaphore-17.bin");
            semaphore17_witness
        }
        18_u16 => {
            graph!(semaphore18, "../witness_graph/semaphore-18.bin");
            semaphore18_witness
        }
        19_u16 => {
            graph!(semaphore19, "../witness_graph/semaphore-19.bin");
            semaphore19_witness
        }
        20_u16 => {
            graph!(semaphore20, "../witness_graph/semaphore-20.bin");
            semaphore20_witness
        }
        21_u16 => {
            graph!(semaphore21, "../witness_graph/semaphore-21.bin");
            semaphore21_witness
        }
        22_u16 => {
            graph!(semaphore22, "../witness_graph/semaphore-22.bin");
            semaphore22_witness
        }
        23_u16 => {
            graph!(semaphore23, "../witness_graph/semaphore-23.bin");
            semaphore23_witness
        }
        24_u16 => {
            graph!(semaphore24, "../witness_graph/semaphore-24.bin");
            semaphore24_witness
        }
        25_u16 => {
            graph!(semaphore25, "../witness_graph/semaphore-25.bin");
            semaphore25_witness
        }
        26_u16 => {
            graph!(semaphore26, "../witness_graph/semaphore-26.bin");
            semaphore26_witness
        }
        27_u16 => {
            graph!(semaphore27, "../witness_graph/semaphore-27.bin");
            semaphore27_witness
        }
        28_u16 => {
            graph!(semaphore28, "../witness_graph/semaphore-28.bin");
            semaphore28_witness
        }
        29_u16 => {
            graph!(semaphore29, "../witness_graph/semaphore-29.bin");
            semaphore29_witness
        }
        30_u16 => {
            graph!(semaphore30, "../witness_graph/semaphore-30.bin");
            semaphore30_witness
        }
        31_u16 => {
            graph!(semaphore31, "../witness_graph/semaphore-31.bin");
            semaphore31_witness
        }
        32_u16 => {
            graph!(semaphore32, "../witness_graph/semaphore-32.bin");
            semaphore32_witness
        }
        _ => panic!("Unsupported depth"),
    }
}
