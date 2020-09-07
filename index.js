const crypto = require('crypto')

const createSHA = secret => {
  const sha256 = crypto.createHash('sha256')
  sha256.update(secret)

  return sha256
}

const encrypt = (key, text) => {
  const sha = createSHA(key)
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv('aes-256-ctr', sha.digest(), iv)
  const cipherText = cipher.update(text)

  const encrypted = Buffer.concat([iv, cipherText, cipher.final()]).toString('base64')

  return encrypted
}

const decrypt = (key, encrypted) => {
  const sha = createSHA(key)

  const input = Buffer.from(encrypted, 'base64')

  const iv = input.slice(0, 16)
  const decipher = crypto.createDecipheriv('aes-256-ctr', sha.digest(), iv)

  const cipherText = input.slice(16)
  const plainText = decipher.update(cipherText) + decipher.final()

  return plainText
}

/*
  Alice, Bob and Eve agrees on using the same parameters for the key exchanging
*/
const alice = crypto.createDiffieHellman(1024)
const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator())
const eve = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator())

/*
  Then they use these parameters to generate their public keys
*/
alice.generateKeys()
bob.generateKeys()
eve.generateKeys()

/*
  Now, alice and bob exchange with each other their public keys
  Eve uses this as an opportunity to get Alice's public key
*/
const aliceSecret = alice.computeSecret(bob.getPublicKey())
const bobSecret = bob.computeSecret(alice.getPublicKey())
const eveSecret = eve.computeSecret(alice.getPublicKey())

/*
  Alice sends bob a message, using the Shared Secret she now has with Bob
  This secret was built using Bob's public key she received earlier
*/
const message = 'hello, bob!'
const encrypted = encrypt(aliceSecret, message)

/*
  When Bob receives Alice's message, he uses their Shared Secret to decrypt
  the message
*/
const decrypted = decrypt(bobSecret, encrypted)

/*
  Eve tries to decrypt the message using Alice's public key, but the Secret
  that was built for her is different from the one Bob and Alice are sharing
*/
const intercepted = decrypt(eveSecret, encrypted)

console.log({
  alice: {
    publicKey: alice.getPublicKey().toString('hex'),
    secret: aliceSecret.toString('hex'),
  },
  bob: {
    publicKey: bob.getPublicKey().toString('hex'),
    secret: bobSecret.toString('hex'),
  },
  eve: {
    publicKey: eve.getPublicKey().toString('hex'),
    secret: eveSecret.toString('hex')
  },
  data: {
    decrypted,
    encrypted,
    intercepted,
  },
})
