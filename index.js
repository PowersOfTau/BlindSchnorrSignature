const elliptic = require('elliptic');
const secp256k1 = elliptic.ec('secp256k1');
const curve = secp256k1.curve;
const BN = require('bn.js');
const zc = require('@zilliqa-js/crypto');
const hashjs = require('hash.js');

//Generate new signer private key for experiment
pvtkeyHex = zc.schnorr.generatePrivateKey();
pvtkeyBN = new BN(pvtkeyHex,16);

//Get signer public key from private key
pubkeyHex = zc.getPubKeyFromPrivateKey(pvtkeyHex);
pubkeyBuf = Buffer.from(pubkeyHex,'hex');
pubkeyBN = new BN(pubkeyHex,16);


/** At User **/
// Creating msg hash buf
msgBuf = Buffer.from("vikram");
msgHash = hashjs.sha256().update(msgBuf).digest('hex');
msgHashBuf = Buffer.from(msgHash);


/** At Signer **/

// Get k not zero and less than curve.n
k = new BN(zc.randomBytes(32),16);
while(k.isZero() || k.gte(curve.n)){
	k = new BN(zc.randomBytes(32),16);
}

// Q = k.G
Q = curve.g.mul(k);


// --> Signer Send Q to User


/** At User **/

// Get random alpha and beta 
alpha = new BN(zc.randomBytes(32),16);
beta = new BN(zc.randomBytes(32),16);

// alphaG = alpha.G
alphaG = curve.g.mul(alpha);


// beta.X here X is pubkeyBuf.
//beta is BN and X(Public Key) is Buffer, so convert X to point using decode
pubkeyDecodedPoint = curve.decodePoint(pubkeyBuf);
// betaX = beta.X
betaX = pubkeyDecodedPoint.mul(beta);

// Q` = Q + alpha.G + beta.X
Qdash = Q.add(alphaG);
Qdash = Qdash.add(betaX);

// Q` encode and get BN
Qcompressed = new BN(Qdash.encodeCompressed());

// C` = Hash(Q || X || msgH)
Cdash = zc.schnorr.hash(Qcompressed,pubkeyBuf,msgHashBuf);
Cdash = Cdash.umod(curve.n);

// C = C` - beta
C = Cdash.sub(beta);
C = C.umod(curve.n);


/** At Signer **/
// S = k - C.Y			Y = PrivateKey
CY = C.mul(pvtkeyBN).umod(curve.n);
S = k.sub(CY).umod(curve.n);

// --> Signer send S to User

/** At User **/
//S` = S + alpha
Sdash = S.add(alpha).umod(curve.n);

// r = C` and s = S`
r = Cdash;
s = Sdash;
//Signature is (r,s) or (C`,S`)
sign1 = new zc.Signature({r,s});


//Verify signature using existing Zilliqas' verify() function
console.log(zc.schnorr.verify(msgHashBuf,sign1,pubkeyBuf));


