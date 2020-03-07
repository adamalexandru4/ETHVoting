// var ElectionECCwPrecompile = artifacts.require("ElectionECCwPrecompile");
// var Election = artifacts.require("ElectionECC");
// var Secp256k1Contract = artifacts.require("Secp256k1");
// var ECCMultiplier = artifacts.require("ECCMultiplier.sol");
// var ECCMath = artifacts.require("ECCMath");

// var BigInt = require('big-integer');

// var crypto = require('crypto')
// var BigInteger = require('bigi')
// var ecurve = require('ecurve') 
// var cs = require('coinstring') 
// var createKeccakHash = require('keccak')

// const Web3 = require('web3');
// const web3 = new Web3(new Web3.providers.WebsocketProvider('ws://localhost:8545'));


// function random(bytes){
//     do {
//         var k = BigInteger.fromByteArrayUnsigned(crypto.randomBytes(bytes));
//     } while (k.toString() == "0" && k.gcd(n).toString() != "1")
//     return k;
// }

// function isOnCurve (x,y) {
//     var x = x;
//     var y = y;
//     var a = ecurve.getCurveByName('secp256k1').a;
//     var b = ecurve.getCurveByName('secp256k1').b;
//     var p = ecurve.getCurveByName('secp256k1').p;

//     // Check that xQ and yQ are integers in the interval [0, p - 1]
//     if (x.signum() < 0 || x.compareTo(p) >= 0) return false
//     if (y.signum() < 0 || y.compareTo(p) >= 0) return false

//     // and check that y^2 = x^3 + ax + b (mod p)
//     var lhs = y.square().mod(p);
//     var rhs = x.pow(3).add(a.multiply(x)).add(b).mod(p);
//     return lhs.equals(rhs);
// }

// function multiply(inp,k){
//     var str = inp.multiply(k).toString().replace("(","").replace(")","");
//     var arr = str.split(",").map(val => String(val));
//     arr [0] = BigInteger.fromBuffer(arr[0]);
//     arr [1] = BigInteger.fromBuffer(arr[1]);

//     return ecurve.Point.fromAffine(ecparams,arr[0],arr[1]);
// }

// function add(inp,k){
//     var str = inp.add(k).toString().replace("(","").replace(")","");
//     var arr = str.split(",").map(val => String(val));
//     arr [0] = BigInteger.fromBuffer(arr[0]);
//     arr [1] = BigInteger.fromBuffer(arr[1]);

//     return ecurve.Point.fromAffine(ecparams,arr[0],arr[1]);
// }

// function toHex(inp){
//     return BigInteger.fromBuffer(inp.toString(),"hex").toHex();
// }

// function keccak256(inp){
//     return createKeccakHash('keccak256').update(inp.toString()).digest('hex');
// }

// var privateKey = new Buffer("1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd", 'hex')
// var m  = "1";
// var ecparams = ecurve.getCurveByName('secp256k1');
// var curvePt = ecparams.G.multiply(BigInteger.fromBuffer(privateKey));
// var x = curvePt.affineX.toBuffer(32);
// var y = curvePt.affineY.toBuffer(32);

// var G = ecparams.G;
// var n = ecparams.n;

// contract('ElectionECC', function(accounts) {

//     let electionContractInstance;

//     it("Organizer should be able to register eligible voters", function() {
//         return Election.deployed().then(function(instance) {
//             electionContractInstance = instance;
//             instance.addEligibleVoter(accounts[1]);
//             return instance.eligibleVoters.call(accounts[1]);
//         }).then(function(member) {
//             assert.equal(member[0], true, "Second account should be registered already");
//         });
//     });

//     it("Election with Secp256k1 test", async () => {

//         var cP = [], sG = [], sum = [], affineSum = [];

//         await ECCMultiplier.deployed().then(function(instance) {
//             return instance.multiply(
//                             "0x460d4f9987b75eac748f5b7329c17da00c384635d38419b7c570b6d701453d77",
//                             ["0xd0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6f",
//                             "0xbdd594388756a7beaf73b4822bc22d36e9bda7db82df2b8b623673eefc0b7495",
//                             ,"1"],
//                             {
//                                 from: accounts[1]
//                             });
//         }).then(function(member) {
//             cP[0] = web3.utils.numberToHex(member[0]).toString();
//             cP[1] = web3.utils.numberToHex(member[1]).toString();
//             cP[2] = web3.utils.numberToHex(member[2]).toString();
//         });

//         await ECCMultiplier.deployed().then(function(instance) {
//             return instance.multiply(
//                             "0xf801ebaa64b1a38f84005652ca5b8a41d06ba5b52f21063d2ab1069307fb5b6a",
//                             ["0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
//                             "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
//                             ,"1"],
//                             {
//                                 from: accounts[1]
//                             });
//         }).then(function(member) {
//             sG[0] = web3.utils.numberToHex(member[0]).toString();
//             sG[1] = web3.utils.numberToHex(member[1]).toString();
//             sG[2] = web3.utils.numberToHex(member[2]).toString();
//         });

        
//         await Secp256k1Contract.deployed().then(function(instance) {
//             return instance._add(
//                             cP, sG,
//                             {
//                                 from: accounts[1]
//                             });
//         }).then(function(member) {
//             sum[0] = web3.utils.numberToHex(member[0]).toString();
//             sum[1] = web3.utils.numberToHex(member[1]).toString();
//             sum[2] = web3.utils.numberToHex(member[2]).toString();
//         });

//         await ECCMath.deployed().then(function(instance) {
//             return instance.toZ12(
//                             sum, 
//                             "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
//                             {
//                                 from: accounts[1]
//                             });
//         }).then(function(member) {
//             affineSum[0] = web3.utils.numberToHex(member[0]).toString();
//             affineSum[1] = web3.utils.numberToHex(member[1]).toString();
//             affineSum[2] = web3.utils.numberToHex(member[2]).toString();
//         });

//         // console.log("CP--> " + cP[0] + "\n" + cP[1]);
//         // console.log("\nSG--> " + sG[0] + "\n" + sG[1]);
//         // console.log("\nSUM--> " + sum[0] + "\n" + sum[1]);
//         // console.log("\nSUM--> " + affineSum[0] + "\n" + affineSum[1]);
//         // // var result = affineSum[0] % (web3.utils.hexToNumber("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
//         // var result = affineSum[0] % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
//         // console.log("\nPROJECTION-->" + result);
//         // console.log("HASH--> " + keccak256(m + result.toString()));
//     });

//     it("Test blind signature process", function async () {
//         /* STEP 1
//             The signer randomly selects an integer k ∈ Zn, calculates R = kG, and then transmits R to the requester
//         */
//         k = random(32);
//         var R = multiply(G,k);

//         /* STEP 2
//             The requester randomly selects two integers γ and δ ∈ Zn, blinds the message, and then
//             calculates point A = kG + γG + δP = (x, y), t = x (mod n). If t equals zero, then γ and δ should
//             be reselected. The requester calculates c = SHA256 (m || t), c’ = c − δ, where SHA256 is a
//             novel hash function computed with 32-bit words and c’ is the blinded message, and then sends
//             c’ to the signer.
//         */
//         var γ = random(32);
//         var δ = random(32);
//         var A = add(add(R,multiply(G,γ)),multiply(curvePt,δ));
//         var t = A.x.mod(n).toString();
//         var c = BigInteger.fromHex(keccak256(m+t.toString()));

//         console.log("c requester: ");
//         console.log(BigInteger.fromHex(keccak256(m+t.toString())).toString());

//         var cBlinded = c.subtract(δ);

//         /* STEP 3
//             The signer calculates the blind signature s’ = k − c’d, and then sends it to the requester.
//         */
//         var sBlind = k.subtract(cBlinded.multiply(BigInteger.fromBuffer(privateKey)));

//         /* STEP 4
//             The requester calculates s = s’ + γ, and (c, s) is the signature on m.
//         */
//         var s = sBlind.add(γ);

//         /* STEP 5
//             Both the requester and signer can verify the signature (c, s) through the formation
//             c = SHA256(m || Rx(cP + sG) mod n)
//         */

//         var toHash = add(multiply(curvePt,c.mod(n)),multiply(ecparams.G,s.mod(n))).x.mod(n)
//         console.log("C: ");
//         console.log(BigInteger.fromHex(keccak256(m+toHash)).toString());

//         console.log("s: ");
//         console.log(s.mod(n).toString());

//         console.log("hashvote: ")
//         console.log(BigInteger.fromHex(keccak256(m)).toString());
           
//         return Election.deployed().then(function(instance) {
//             electionInstance = instance;
//             return electionInstance.verifyBlindSig(
//                 m,
//                 "36569675563270980802762714306156177901149277261141117320653538205171502807189",
//                 "6584969667293602680567734539575163142389903381909774456551685991814241531484");
//                 // BigInteger.fromHex(keccak256(m+toHash)).toString(),
//                 // s.mod(n).toString());
//         }).then(function(member) {
//             console.log(member.toString());
//         });

//     //     return Election.deployed().then(function(instance) {
//     //         electionContractInstance = instance;
//     //        return electionContractInstance.verifyBlindSig(
//     //                         m,
//     //                         "0x" + c.mod(n).toHex(),
//     //                         "0x" + s.mod(n).toHex(),
//     //                         {
//     //                             from: accounts[1]
//     //                         });
//     //     }).then(function(member) {
//     //         console.log(member.toString());
//     // //         //console.log(new BigNumber(member[1]).toString(16));
//     // //         //console.log(new BigNumber(member[2]).toString(16));
//     //     });
//     });
// });