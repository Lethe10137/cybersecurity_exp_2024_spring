use num_bigint::{BigInt, BigUint, ToBigInt};
use rand::{rngs::StdRng, Rng};
use rug::Integer;

#[derive(Debug)]
pub struct PaillierPublicKey {
    pub n: BigUint,
    pub g: BigUint,
}

fn euler(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    let mut a0: BigUint = a.clone();
    let mut a1: BigInt = 1.into();
    let mut a2: BigInt = 0.into();
    let mut b0: BigUint = b.clone();
    let mut b1: BigInt = 0.into();
    let mut b2: BigInt = 1.into();
    loop {
        if a0 == 0u32.into() {
            return (b0, b1, b2);
        }
        if b0 == 0u32.into() {
            return (a0, a1, a2);
        }
        if a0 > b0 {
            let k = &a0 / &b0;
            a0 -= &k * &b0;
            let k = k.to_bigint().unwrap();
            a1 -= &k * &b1;
            a2 -= &k * &b2;
        } else {
            let k = &b0 / &a0;
            b0 -= &k * &a0;
            let k = k.to_bigint().unwrap();
            b1 -= &k * &a1;
            b2 -= &k * &a2;
        }
    }
}

fn get_big_prime(bits: usize, rng: &mut StdRng) -> BigUint {
    let mut len = bits / 8;
    if len < 1 {
        len = 1;
    }
    let mut random_bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    if random_bytes[0] == 0 {
        random_bytes[0] = 1;
    }

    let a: Integer = Integer::from_digits(
        random_bytes.into_boxed_slice().as_ref(),
        rug::integer::Order::Msf,
    );
    let prime = a.next_prime();

    let digits: Vec<u32> = prime.to_digits(rug::integer::Order::Lsf);
    let digits = digits.into_boxed_slice();

    let result = BigUint::from_slice(&digits);
    result
}

fn get_random(module: &BigUint, rng: &mut StdRng, coprime: Option<&BigUint>) -> BigUint {
    loop {
        let r: Vec<u32> = module
            .to_u32_digits()
            .into_iter()
            .map(|v: u32| {
                let x: u32 = rng.gen();
                v ^ x
            })
            .collect();
        let r = r.into_boxed_slice();
        let r = BigUint::from_slice(&r);
        let result = &r % module;
        if coprime.is_some() {
            let (gcd, _, _) = euler(coprime.unwrap(), &r);
            if gcd != 1u32.into() {
                continue;
            }
        }
        return result;
    }
}

fn func_l(x: &BigUint, n: &BigUint) -> Option<BigUint> {
    if x % n != 1u32.into() {
        None
    } else {
        let y = x - 1u32;
        Some(y / n)
    }
}

impl PaillierPublicKey {
    pub fn encrypt(&self, plaintext: &BigUint, rng: &mut StdRng) -> BigUint {
        // println!("g = {}, m = {}", &self.g, &plaintext);
        let n_2 = &self.n * &self.n;
        // println!("n_2 = {}", &n_2);

        let v1 = &self.g.modpow(&plaintext, &n_2);
        // println!("g^m = {}", &v1);
        let v2 = get_random(&n_2, rng, Some(&self.n)).modpow(&self.n, &n_2);
        // println!("r^n = {}", &v2);
        (v1 * v2) % n_2
    }
}
#[derive(Debug)]
pub struct PaillierPrivateKey {
    lambda: BigUint,
    mu: BigUint,
    n: BigUint,
}

impl PaillierPrivateKey {
    pub fn decrypt(&self, ciphertext: &BigUint) -> Option<BigUint> {
        let x = ciphertext.modpow(&self.lambda, &(&self.n * &self.n));
        if let Some(l) = func_l(&x, &self.n) {
            Some((l * &self.mu) % &self.n)
        } else {
            None
        }
    }
}
#[derive(Debug)]
pub struct PaillierKeyPair {
    pub private: PaillierPrivateKey,
    pub public: PaillierPublicKey,
}

impl Into<(PaillierPublicKey, PaillierPrivateKey)> for PaillierKeyPair {
    fn into(self) -> (PaillierPublicKey, PaillierPrivateKey) {
        (self.public, self.private)
    }
}

impl PaillierKeyPair {
    pub fn new(bits: usize, rng: &mut StdRng) -> Self {
        let mut p = get_big_prime(bits, rng);
        let mut q = get_big_prime(bits, rng);
        let n = &p * &q;
        let n_2 = &n * &n;
        p -= BigUint::from(1u32);
        q -= BigUint::from(1u32);

        let (gcd, _, _) = euler(&p, &q);
        let lambda = (&p / gcd) * &q;

        loop {
            let a = get_random(&n, rng, None);

            let g = &n * &a + BigUint::from(1u32);
            if let Some(l) = func_l(&g.modpow(&lambda, &n_2), &n) {
                let (gcd, k1, _) = euler(&l, &n);
                // gcd = k1 * l + k2 * n
                let signed_n = &n.to_bigint().unwrap();
                if gcd == 1u32.into() {
                    let mu = ((k1 % signed_n) + signed_n) % signed_n;
                    let mu = mu.to_biguint().unwrap();
                    return PaillierKeyPair {
                        private: PaillierPrivateKey {
                            lambda: lambda,
                            mu: mu,
                            n: n.clone(),
                        },
                        public: PaillierPublicKey { n: n, g: g },
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_euler() {
        let mut rng = StdRng::from_entropy();
        for _ in 0..100 {
            let a = get_random(&(std::u32::MAX.into()), &mut rng, None);
            let b = get_random(&(std::u32::MAX.into()), &mut rng, None);
            let (gcd, k1, k2) = euler(&a, &b);
            let test = k1 * a.to_bigint().unwrap() + k2 * b.to_bigint().unwrap();
            let test = test.to_biguint().unwrap();
            assert_eq!(gcd, test);
        }
    }

    #[test]
    fn new_pair() {
        let mut rng = StdRng::from_entropy();
        let key_pair = PaillierKeyPair::new(100, &mut rng);
        dbg!(key_pair);
    }

    #[test]
    fn test_cypher() {
        let n: BigUint = 15u32.into();
        let g = 16u32.into();
        let lambda = 4u32.into();
        let mu = 4u32.into();
        let pubkey = PaillierPublicKey { n: n.clone(), g };
        let prikey = PaillierPrivateKey { lambda, mu, n };

        let mut rng = StdRng::from_entropy();

        let m1: BigUint = 7u32.into();
        let m2: BigUint = 2u32.into();
        let d1 = pubkey.encrypt(&m1, &mut rng);
        let d2 = pubkey.encrypt(&m2, &mut rng);

        let d1d2 = &d1 * &d2;
        let result = prikey.decrypt(&d1d2);

        assert_eq!(Some(m1 + m2), result);
    }

    #[test]
    fn fuzz() {
        let mut rng = StdRng::from_entropy();

        let keys = PaillierKeyPair::new(1024, &mut rng);

        dbg!(&keys);

        let m1: BigUint = get_random(&BigUint::from(std::u128::MAX), &mut rng, None);
        let m2: BigUint = get_random(&BigUint::from(std::u128::MAX), &mut rng, None);
        let d1 = keys.public.encrypt(&m1, &mut rng);
        let d2 = keys.public.encrypt(&m2, &mut rng);

        dbg!(&d1, &d2);

        let d1d2 = &d1 * &d2;
        let result = keys.private.decrypt(&d1d2);

        assert_eq!(Some(m1 + m2), result);
    }
}
