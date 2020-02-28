const fs = require('fs');
const chai = require('chai');
const zkSnark = require('snarkjs');
const { stringifyBigInts, unstringifyBigInts } = require("../node_modules/snarkjs/src/stringifybigint.js");
const bignum = require('big-integer');
const generateCall = require("../src/generateCall"); // For of snarkjs-cli and modified to get the proof to be sent to the smart-contract
const crypto = require('crypto-browserify');
const paillier = require('../node_modules/paillier-bignum/src/paillier');
const { encryptWithProof, verifyProof } = require('paillier-in-set-zkp');
const Web3 = require('web3');
const web3 = new Web3(new Web3.providers.WebsocketProvider('ws://localhost:8545'));

const assert = chai.assert;


const Verifier = artifacts.require('../contracts/Verifier.sol');
const ADElection = artifacts.require('../contracts/ADElection.sol');

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
            allAccoutns = accounts;
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
            assert.equal(proof.proof.protocol, "original");
        });

        it('Verify proof', () => {
            let vk_verifier = JSON.parse(fs.readFileSync(__dirname + "/myCircuit.vk_verifier", "utf8"));
            assert.isTrue(zkSnark.original.isValid(unstringifyBigInts(vk_verifier), unstringifyBigInts(proof.proof), unstringifyBigInts(proof.publicSignals)));
        }).timeout(10000000);;

    });
});