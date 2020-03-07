var ECCMath = artifacts.require("../contracts/crypto/ECCMath.sol");
var ECCMultiplier = artifacts.require("../contracts/crypto/ECCMultiplier.sol");
var Secp256k1 = artifacts.require("../contracts/crypto/Secp256k1.sol");
var ElectionECC = artifacts.require("../contracts/crypto/ElectionECC.sol");

var preCompiles = artifacts.require("../contracts/crypto/utils/eccPrecompiles.sol");
var stringUtils = artifacts.require("../contracts/crypto/utils/stringUtils.sol");
var ElectionECCwPrecompiled = artifacts.require("../contracts/crypto/ElectionECCwPrecompile.sol");

module.exports = function(deployer) {
    deployer.deploy(ECCMath);
    
    deployer.link(ECCMath, Secp256k1);
    deployer.deploy(Secp256k1);

    deployer.link(ECCMath, ECCMultiplier);
    deployer.link(Secp256k1, ECCMultiplier);
    deployer.deploy(ECCMultiplier);

    deployer.link(ECCMath, ElectionECC);
    deployer.link(Secp256k1, ElectionECC);
    deployer.link(ECCMultiplier, ElectionECC);
    deployer.deploy(ElectionECC, "How much do you like me?");

    deployer.deploy(preCompiles);
    deployer.link(preCompiles, ElectionECCwPrecompiled);
    deployer.deploy(ElectionECCwPrecompiled, "How much do you like ETH?");
};