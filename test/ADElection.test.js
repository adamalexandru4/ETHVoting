const fs = require('fs');
const chai = require('chai');
const zkSnark = require('snarkjs');
const { stringifyBigInts, unstringifyBigInts } = require("../node_modules/snarkjs/src/stringifybigint.js");
const bignum = require('big-integer');
const generateCall = require("../src/generateCall"); // For of snarkjs-cli and modified to get the proof to be sent to the smart-contract
const crypto = require('crypto-browserify');
const paillier = require('paillier-js');
const Stealth = require('stealth_eth');
const coinkey = require('coinkey');
const ethereum = require('ethereumjs-utils');
const { encryptWithProof, verifyProof } = require('paillier-in-set-zkp');
const EthereumTX = require('ethereumjs-tx').Transaction

const Web3 = require('web3');
const web3 = new Web3(new Web3.providers.WebsocketProvider('ws://localhost:8545'));

const assert = chai.assert;


const Verifier = artifacts.require('../contracts/Verifier.sol');
const ADElection = artifacts.require('../contracts/ADElection.sol');

var stealth = {};
var ethStealthAddress = {};
var pubKeyToRecover = {};
var opMarker = {};

var compressedPubScanKeys = '';

// Workaround to solve paillier-js bigInt.rand not found when running with yarn
let bigInt = bignum;
bigInt.rand = function (bitLength) {
    let bytes = bitLength / 8;
    let buf = Buffer.alloc(bytes);
    crypto.randomFillSync(buf);
    buf[0] = buf[0] | 128;  // first bit to 1 -> to get the necessary bitLength
    return bigInt.fromArray([...buf], 256);
};

contract('ADElection', async accounts => {
    describe('Install contracts and test', () => {
        beforeEach(async () => {
            const publicKey = JSON.parse(fs.readFileSync(__dirname + '/voteenc_publicKey.json', 'utf-8'));
            let _publicKey = JSON.stringify({
                'n': stringifyBigInts(publicKey.n.toString()),
                'g': stringifyBigInts(publicKey.g.toString()),
                '_n2': stringifyBigInts(publicKey._n2.toString()),
                'bitLength': publicKey.bitLength
            });

            ADElectionVerifier = await Verifier.new(accounts[0]);
            verifierAddress = await ADElectionVerifier.address;
            ADElectionInstance = await ADElection.new(web3.utils.toHex('Alegeri prezidentiale'), web3.utils.toHex(_publicKey), verifierAddress, accounts[1]);
            ADElectionABI = await ADElectionInstance.abi;
            ADElectionAddress = await ADElectionInstance.address;
            allAccounts = accounts;
        });

        it('Test ADElection contract', async () => {
            result = await ADElectionInstance.ballotName().then(function (res) {
                return res;
            });
            // Check if name of the election is the same
            assert.equal(result.toString(), '0x416c6567657269207072657a6964656e7469616c65');
        });

        it('Verify the ZK Vote Proof on smart-contract', async () => {
            let proof = JSON.parse(fs.readFileSync(__dirname + "/setup_zksnark/proof.json", "utf8"));
            let publicSignals = JSON.parse(fs.readFileSync(__dirname + "/setup_zksnark/public.json", "utf8"));

            let verifyCall = await generateCall(publicSignals, proof);
            result = await ADElectionVerifier.verifyProof.call(verifyCall.a, verifyCall.ap, verifyCall.b, verifyCall.bp, verifyCall.c, verifyCall.cp, verifyCall.h, verifyCall.kp, verifyCall.inputs);
            assert.isTrue(result);
        });

        it("Voter create scan keys, encode pub+scan public keys and send it to the Admin; organisezer receives" +
         + " pubScanKey from voter, create a random stealth wallet and sent it to the smart-contract", async () => {

            // Generate two key pairs
            var payloadKeyPair = coinkey.createRandom();
            var scanKeyPair = coinkey.createRandom();

            stealth = new Stealth({
                payloadPrivKey: payloadKeyPair.privateKey,
                payloadPubKey:  payloadKeyPair.publicKey,
                scanPrivKey: scanKeyPair.privateKey,
                scanPubKey: scanKeyPair.publicKey
            });
    
            // This should be sent by the voter and received by the admin after that
            compressedPubScanKeys = stealth.toString();

            // ADMIN PART
            var keypair = coinkey.createRandom();
            
            // Generate payment address
            ethStealthAddress = ethereum.addHexPrefix(stealth.genEthPaymentAddress(keypair.privateKey));
            pubKeyToRecover = keypair.publicKey.toString('hex');
            opMarker = stealth.genPaymentPubKeyHash(keypair.privateKey).toString('hex');

            var canVote = await ADElectionInstance.fakeVoters(ethStealthAddress);
            assert.isNotTrue(canVote.canVote);

            // Add the stealth address as fake voter to the smart contract
            await ADElectionInstance.addFakeVoter(ethStealthAddress, web3.utils.toHex(pubKeyToRecover), web3.utils.toHex(opMarker))
                .then(async () => {
                    // FUND the eth account, it could be done from contract too
                    let fundSent = await web3.eth.sendTransaction({
                        from: accounts[0],
                        to: ethStealthAddress,
                        value: web3.utils.toHex(web3.utils.toWei('1', 'ether'))
                    });
                    assert.exists(fundSent.transactionHash);
                });

            assert.isTrue(ethereum.isValidAddress(ethStealthAddress));

            canVote = await ADElectionInstance.fakeVoterArray(await ADElectionInstance.fakeVoters(ethStealthAddress)); 
            assert.isTrue(canVote.canVote);
        });
    });

    describe('Create vote and ZK-Snarks of vote', () => {
        let votes = {};

        // Setting up the vote
        let voter = "0x965cd5b715904c37fcebdcb912c672230103adef";
        let signature = "0x234587623459623459782346592346759234856723985762398756324985762349587623459876234578965978234659823469324876324978632457892364879234697853467896";
    
        // votes.question1 = [0, 0, 1, 0];
        // votes.question2 = [1, 0];
        // votes.question3 = [0, 0, 0, 1];
        votes.question1 = [1, 0, 0, 0];
        votes.question2 = [0, 1];
        votes.question3 = [1, 0, 0, 0];

        let count_votes = 0;
        let question1TotalVotes = 0, question2TotalVotes = 0, question3TotalVotes = 0;

        for(let i = 0; i < votes.question1.length; i ++) {
            if(votes.question1[i] == 1) {
                question1TotalVotes++;
                count_votes++;
            }
        }

        for(let i = 0; i < votes.question2.length; i ++) {
            if(votes.question2[i] == 1) {
                question2TotalVotes++;
                count_votes++;
            }
        }

        for(let i = 0; i < votes.question3.length; i ++) {
            if(votes.question3[i] == 1) {
                question3TotalVotes++;
                count_votes++;
            }
        }

        let question1TotalOptions = votes.question1.length;
        let question2TotalOptions = votes.question2.length;
        let question3TotalOptions = votes.question3.length;

        let p = 1234;
        let rcm = [1234, 13134];

        const inputArray = {
            "voter": voter.toString(),
            "signature": signature.toString(),
            "question1": votes.question1,
            "question2": votes.question2,
            "question3": votes.question3,
            "p": p,
            "rcm": rcm,
            "question1TotalOptions": question1TotalOptions,
            "question2TotalOptions": question2TotalOptions,
            "question3TotalOptions": question3TotalOptions,
            "question1TotalVotes": question1TotalVotes,
            "question2TotalVotes": question2TotalVotes,
            "question3TotalVotes": question3TotalVotes,
            "totalVotes": count_votes
        }

        let circuit = {};
        let setup = {};
        let witness = {};
        let proof = {};
        let publicKey = {};
        let privateKey = {};

        it("Load a circuit", () => {
            const circuitDef = JSON.parse(fs.readFileSync(__dirname + "/setup_zksnark/circuit.json", "utf8"));
            circuit = new zkSnark.Circuit(circuitDef);
            assert.equal(circuit.nOutputs, 4);
        });

        it("Create a trusted setup", () => {
            // Trusted setup
            setup = zkSnark.original.setup(circuit);
            fs.writeFileSync(__dirname + "/myCircuit.vk_proof", JSON.stringify(stringifyBigInts(setup.vk_proof)), "utf8");
            fs.writeFileSync(__dirname + "/myCircuit.vk_verifier", JSON.stringify(stringifyBigInts(setup.vk_verifier)), "utf8");
            
            setup.toxic  // Must be discarded.
            assert.equal(setup.vk_verifier.nPublic, 7);
        }).timeout(10000000);

        it('Generate proof', () => {
            witness = circuit.calculateWitness(inputArray);
            let vk_proof = JSON.parse(fs.readFileSync(__dirname + "/myCircuit.vk_proof", "utf8"));
            proof = zkSnark.original.genProof(unstringifyBigInts(vk_proof), unstringifyBigInts(witness));
            console.log(proof);
            assert.equal(proof.proof.protocol, "original");
        });

        it('Verify proof', () => {
            let vk_verifier = JSON.parse(fs.readFileSync(__dirname + "/myCircuit.vk_verifier", "utf8"));
            assert.isTrue(zkSnark.original.isValid(unstringifyBigInts(vk_verifier), unstringifyBigInts(proof.proof), unstringifyBigInts(proof.publicSignals)));
        }).timeout(10000000);

    });

    describe("Encrypt, count, decrypt and test votes result proof", () => {
        let votes = {};

        let voter = "0x965cd5b715904c37fcebdcb912c672230103adef";
        let signature = "0x234587623459623459782346592346759234856723985762398756324985762349587623459876234578965978234659823469324876324978632457892364879234697853467896";
    
        votes.question1 = [1, 0, 0, 0];
        votes.question2 = [0, 1];
        votes.question3 = [1, 0, 0, 0];

        let voteCount = 0;
        let votesArray = [];

        let publicKey = '';
        
        const _privateKey = JSON.parse(fs.readFileSync(__dirname + "/voteenc_privateKey.json", "utf8"));
        let privateKey = new paillier.PrivateKey(bignum(_privateKey.lambda), bignum(_privateKey.mu), bignum(_privateKey.p), bignum(_privateKey.q), bignum(_privateKey.publicKey));

        it("Encrypt votes", async () => {
            let result = await ADElectionInstance.encryptionPubKey().then(function (res) {
                return (web3.utils.hexToAscii(res));
            });

            const _publicKey = JSON.parse(result);
            publicKey = new paillier.PublicKey(bignum(_publicKey.n), bignum(_publicKey.g));
            assert(publicKey.bitLength == '1024');

            for(let i = 0; i < votes.question1.length; i ++) {
                voteCount += votes.question1[i];
                // Convert to BN
                var bn1 = bignum(votes.question1[i]).mod(publicKey.n);
                // Fix for negative numbers
                while (bn1.lt(0)) bn1 = bn1.add(publicKey.n); 
                votes.question1[i] = publicKey.encrypt(bn1);
            }

            for(let i = 0; i < votes.question2.length; i ++) {
                voteCount += votes.question2[i];
                // Convert to BN
                let bn2 = bignum(votes.question2[i]).mod(publicKey.n);
                // Fix for negative numbers
                while (bn2.lt(0)) bn2 = bn2.add(publicKey.n); 
                votes.question2[i] = publicKey.encrypt(bn2);
            }

            for(let i = 0; i < votes.question3.length; i ++) {
                voteCount += votes.question3[i];
                // Convert to BN
                let bn3 = bignum(votes.question3[i]).mod(publicKey.n);
                // Fix for negative numbers
                while (bn3.lt(0)) bn3 = bn3.add(publicKey.n); 
                votes.question3[i] = publicKey.encrypt(bn3);
            }

            var encryptedSum;
            encryptedSum = publicKey.addition(votes.question1[0], votes.question2[1], votes.question3[0]);

            let decryptedSum;
            decryptedSum = privateKey.decrypt(encryptedSum);
            assert.equal(bignum(3).toString(), decryptedSum.toString());
        });

        it("Register encrypted votes on the blockchain", async () => {
            // Reopen connection
            let web3 = new Web3(new Web3.providers.WebsocketProvider('ws://localhost:8545'));

            // Get access to the Fake Voter Wallet (Stealth)
            let opMarkerBuffer = new Buffer(opMarker, 'hex');
            let pubKeyToRecoverBuffer = new Buffer(pubKeyToRecover, 'hex');

            let keypair = stealth.checkPaymentPubKeyHash(pubKeyToRecoverBuffer, opMarkerBuffer);
            assert.isNotNull(keypair); // if it's null the payment is not mine

            let ethAddress = '0x' + ethereum.privateToAddress(keypair.privKey).toString('hex');

            let canVote = await ADElectionInstance.fakeVoterArray(await ADElectionInstance.fakeVoters(ethAddress));
            assert.isTrue(canVote.canVote);

            // Recovered private key
            let privateKey = new Buffer(keypair.privKey, 'hex')

            let hexVotes = {};
            hexVotes.question1 = [];
            hexVotes.question2 = [];
            hexVotes.question3 = [];

            for(let i = 0; i < votes.question1.length; i ++) {
                hexVotes.question1[i] = web3.utils.toHex(votes.question1[i].toString());
            }
            for(let i = 0; i < votes.question2.length; i ++) {
                hexVotes.question2[i] = web3.utils.toHex(votes.question2[i].toString());
            }
            for(let i = 0; i < votes.question3.length; i ++) {
                hexVotes.question3[i] = web3.utils.toHex(votes.question3[i].toString());
            }

            const estimateGas = await ADElectionInstance.addVote.estimateGas(hexVotes.question1, 
                                                                            hexVotes.question2, 
                                                                            hexVotes.question3,
                                                                            web3.utils.toHex('commit1'), 
                                                                            { from: ethAddress});
            const contract = new web3.eth.Contract(ADElectionABI, ADElectionAddress);
            const method = contract.methods.addVote(hexVotes.question1, 
                                                    hexVotes.question2, 
                                                    hexVotes.question3,
                                                    web3.utils.toHex('commit1'));
            const encodedABI = method.encodeABI();
            const nonceValue = web3.utils.toHex(await web3.eth.getTransactionCount(ethAddress));

            let rawTx = {
                nonce: nonceValue,
                from: ethAddress,
                to: ADElectionAddress,
                gasPrice: web3.utils.toHex(web3.utils.toWei('6', 'gwei')),
                gasLimit: web3.utils.toHex('10000'),
                gas: estimateGas,
                data: encodedABI
            };

            let unsignedTx = new EthereumTX(rawTx);
            unsignedTx.sign(privateKey);

            let serializedTx = unsignedTx.serialize();

            let tx = await web3.eth.sendSignedTransaction('0x' + serializedTx.toString('hex'));

            canVote = await ADElectionInstance.fakeVoterArray(await ADElectionInstance.fakeVoters(ethAddress));
            assert.isNotTrue(canVote.canVote);
            assert.isTrue(canVote.voted);
        });

        it("Recover votes from blockchain and sum all togheter", async () => {
            let encryptedVotes = [{}];
            let contractVotes = [];

            encryptedVotes.question1 = [];
            encryptedVotes.question2 = [];
            encryptedVotes.question3 = [];


            let votesCount = await ADElectionInstance.votesCount();
            assert(Number(votesCount) > 0);

            // Get the private key from JSON file
            const _privateKey = JSON.parse(fs.readFileSync("test/voteenc_privateKey.json", "utf8"));
            privateKey = new paillier.PrivateKey(bignum(_privateKey.lambda), bignum(_privateKey.mu), bignum(_privateKey.p), bignum(_privateKey.q), bignum(_privateKey.publicKey));

            let encryptedTotalSum = 0;
            let encryptedQuestion1Sum, encryptedQuestion2Sum, encryptedQuestion3Sum;

            let bn4 = bignum(encryptedTotalSum).mod(publicKey.n);
            while (bn4.lt(0)) bn4 = bn4.add(publicKey.n);
            encryptedTotalSum = publicKey.encrypt(bn4);

            for(let i = 0; i < votesCount; i ++) {
                contractVotes = await ADElectionInstance.getVoteAnswers(i);
                encryptedVotes[i].question1 = contractVotes[0];
                encryptedVotes[i].question2 = contractVotes[1];
                encryptedVotes[i].question3 = contractVotes[2];

                for(let j = 0; j < contractVotes[0].length; j ++) {
                    if(encryptedQuestion1Sum == null) {
                        encryptedQuestion1Sum = 0;
                        let bn5 = bignum(encryptedQuestion1Sum).mod(publicKey.n);
                        while (bn5.lt(0)) bn5 = bn5.add(publicKey.n);
                        encryptedQuestion1Sum = publicKey.encrypt(bn5);
                    }
                    encryptedTotalSum = publicKey.addition(bignum(web3.utils.hexToAscii(encryptedVotes[i].question1[j])), encryptedTotalSum);
                    encryptedQuestion1Sum = publicKey.addition(bignum(web3.utils.hexToAscii(encryptedVotes[i].question1[j])), encryptedQuestion1Sum);
                }

                for(let j = 0; j < contractVotes[1].length; j ++) {
                    if(encryptedQuestion2Sum == null) {
                        encryptedQuestion2Sum = 0;
                        let bn5 = bignum(encryptedQuestion2Sum).mod(publicKey.n);
                        while (bn5.lt(0)) bn5 = bn5.add(publicKey.n);
                        encryptedQuestion2Sum = publicKey.encrypt(bn5);
                    }
                    encryptedTotalSum = publicKey.addition(bignum(web3.utils.hexToAscii(encryptedVotes[i].question2[j])), encryptedTotalSum);
                    encryptedQuestion2Sum = publicKey.addition(bignum(web3.utils.hexToAscii(encryptedVotes[i].question2[j])), encryptedQuestion2Sum);
                }

                for(let j = 0; j < contractVotes[2].length; j ++) {
                    if(encryptedQuestion3Sum == null) {
                        encryptedQuestion3Sum = 0;
                        let bn5 = bignum(encryptedQuestion3Sum).mod(publicKey.n);
                        while (bn5.lt(0)) bn5 = bn5.add(publicKey.n);
                        encryptedQuestion3Sum = publicKey.encrypt(bn5);
                    }
                    encryptedTotalSum = publicKey.addition(bignum(web3.utils.hexToAscii(encryptedVotes[i].question3[j])), encryptedTotalSum);
                    encryptedQuestion3Sum = publicKey.addition(bignum(web3.utils.hexToAscii(encryptedVotes[i].question3[j])), encryptedQuestion3Sum);
                }
            }

            let decryptedTotalSum = privateKey.decrypt(encryptedTotalSum);
            assert.equal(decryptedTotalSum.toString(), voteCount.toString());

            let decryptedQuestion1Sum = privateKey.decrypt(encryptedQuestion1Sum);
            let decryptedQuestion2Sum = privateKey.decrypt(encryptedQuestion2Sum);
            let decryptedQuestion3Sum = privateKey.decrypt(encryptedQuestion3Sum);
            
            assert.equal(decryptedQuestion1Sum.toString(), '1');
            assert.equal(decryptedQuestion2Sum.toString(), '1');
            assert.equal(decryptedQuestion3Sum.toString(), '1');
        });

        it('Create a proof-of-result and test result', () => {
            // Get the public key from smart-contract
            const [cipher, proof] = encryptWithProof(publicKey, voteCount, [voteCount, 10, 20], publicKey.bitLength);
            const result = verifyProof(publicKey, cipher, proof, [voteCount, 10, 20], publicKey.bitLength);
            let decrypted = privateKey.decrypt(cipher);

            assert(result == true && decrypted == voteCount);
        });

    });
});