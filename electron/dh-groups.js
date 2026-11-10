// В Electron вместо OpenSSL используется BoringSSL, а в нём нет DH-групп modp1 и modp2
// («Unknown DH group»). Старые Cisco умеют только diffie-hellman-group1-sha1 (modp2), поэтому
// создаём эти группы сами из простых чисел RFC 2409. Подключать до загрузки ssh2.
const crypto = require('crypto');

const PRIMES = {
  modp1: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff',
  modp2: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff',
};

const original = crypto.createDiffieHellmanGroup;
crypto.createDiffieHellmanGroup = crypto.getDiffieHellman = function (name) {
  try {
    return original.call(crypto, name);
  } catch (err) {
    if (!PRIMES[name]) throw err;
    return crypto.createDiffieHellman(Buffer.from(PRIMES[name], 'hex'), Buffer.from([2]));
  }
};
