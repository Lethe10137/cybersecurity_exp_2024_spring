mod paillier;
use num_bigint::BigUint;
use paillier::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

struct Ballot<const N: usize> {
    data: [BigUint; N],
}

impl<const N: usize> Ballot<N> {
    fn fill_out(candidate: usize, rng: &mut StdRng, publickey: &PaillierPublicKey) -> Self {
        //candidate不在0..N范围，视为无效票，各项都是0
        Ballot {
            data: core::array::from_fn(|i| {
                publickey.encrypt(
                    &BigUint::from(if i == candidate { 1u32 } else { 0u32 }),
                    rng,
                )
            }),
        }
    }
}

struct VoteCounter<const N: usize> {
    data: [BigUint; N],
}

impl<const N: usize> VoteCounter<N> {
    pub fn new() -> Self {
        VoteCounter {
            data: core::array::from_fn(|_| BigUint::from(1u32)),
        }
    }

    pub fn collect_ballot(&mut self, ballot: &Ballot<N>, publickey: &PaillierPublicKey) {
        for i in 0..N {
            self.data[i] *= &ballot.data[i];
            self.data[i] %= &publickey.n * &publickey.n; // mod n**2
        }
    }

    pub fn report(self) -> [BigUint; N] {
        self.data
    }
}

fn main() {
    let mut rng = StdRng::from_entropy();

    //密钥中的p和q大致使用256位

    //生成密钥
    let keys = PaillierKeyPair::new(256, &mut rng);
    let (publickey, privatekey) = keys.into();

    dbg!(&publickey);
    dbg!(&privatekey);

    //候选人总数
    const N: usize = 6;
    //选民总数
    const M: usize = 200;

    let mut trival_count = [0usize; N];

    let votes: Vec<usize> = (0..M)
        .into_iter()
        .map(|_| {
            let vote = rng.gen_range(0..N);
            trival_count[vote] += 1;
            vote
        })
        .collect();

    println!("votes: {:?}", &votes);

    let mut vote_counter = VoteCounter::<N>::new();

    votes
        .into_iter()
        .map(|candidate| {
            //填写选票
            Ballot::<N>::fill_out(candidate, &mut rng, &publickey)
        })
        .map(|ballot| {
            //记票方记票
            vote_counter.collect_ballot(&ballot, &publickey)
        })
        .last();

    let decrypted_result: Vec<BigUint> = vote_counter
        .report()
        .into_iter()
        .map(|ciphertext| {
            //公布方依次解密
            privatekey.decrypt(&ciphertext).unwrap()
        })
        .collect();

    println!("预计的结果：{:?}", trival_count);
    println!("  实际结果：{:?}", decrypted_result);
}
