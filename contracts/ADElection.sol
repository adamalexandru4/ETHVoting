pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2; // for bytes[]

contract ADElection {
    
    struct Votes {
        bytes[] answersQuestion1;
        bytes[] answersQuestion2;
        bytes[] answersQuestion3; 
        bytes32 commitNo;
    }
    
    struct RealVoter {
        address realVoterAddress;
        uint[2] a;
        uint[2] a_p;
        uint[2][2] b;
        uint[2] b_p;
        uint[2] c;
        uint[2] c_p;
        uint[2] h;
        uint[2] k;
        uint[7] input;
        bool voted; 
    }
    
    struct FakeVoter {
        address fakeVoterAddress;
        bytes pubKeyToRecover;
        bytes32 pubKeyHash;
        bool canVote;
        bool voted; 
    }
    
    FakeVoter[] public fakeVoterArray;
    RealVoter[] public realVoterArray;
    Votes[] public votesArray;
    
    mapping(address => uint) public fakeVoters;
    mapping(address => uint) public realVoters;
    mapping(address => uint) public votes;
    
    address public owner;
    address public zkVerifier;
    string public ballotName;
    bytes public encryptionPubKey;
    string public shortName; // for URL, Maybe
    string public typeOfElection;
    
    
    uint public votersCount;
    uint public votesCount;
    uint public voteProofs;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    constructor(string memory _ballotName, bytes memory _encryptionPubKey, address _zkVerifier, address _ownerElection) public {
        owner = _ownerElection;
        ballotName = _ballotName;
        encryptionPubKey = _encryptionPubKey;
        zkVerifier = _zkVerifier;
    }
    
    function addFakeVoter(address _address, bytes memory _pubKeyToRecover, bytes32 _pubKeyHash) public {
        // restrict to authorities
        FakeVoter memory newFakeVoter = FakeVoter(_address, _pubKeyToRecover, _pubKeyHash, true, false);
        fakeVoterArray.push(newFakeVoter);
        
        fakeVoters[_address] = fakeVoterArray.length - 1;
        votersCount++;
    }
    
    function addVote(bytes[] memory answer1, bytes[] memory answer2, bytes[] memory answer3, bytes32 newC) public returns(bool) {
        FakeVoter storage sender = fakeVoterArray[fakeVoters[msg.sender]];
        
        if(sender.voted || !sender.canVote)
            return false;
        
        Votes memory newVote;
        
        if(answer1.length > 0) {
            newVote.answersQuestion1 = answer1;
        }
        if(answer2.length > 0) {
            newVote.answersQuestion2 = answer2;
        } 
        if(answer3.length > 0) {
            newVote.answersQuestion3 = answer3;
        }
        newVote.commitNo = newC; // ????
        
        votesArray.push(newVote);
        votes[msg.sender] = votesArray.length - 1;
        votesCount++;
        
        sender.voted = true;
        sender.canVote = false;
        
        return true;
    }

    function registerVoterProof( uint[2] memory _a, uint[2] memory _a_p, uint[2][2] memory _b, uint[2] memory _b_p,
        uint[2] memory _c, uint[2] memory _c_p, uint[2] memory _h, uint[2] memory _k, uint[7] memory _input) public 
    {
        RealVoter storage sender = realVoterArray[realVoters[msg.sender]];
        require(!sender.voted, "User already voted");
        
        Verify verifier = Verify(zkVerifier);
        require(!verifier.verifyProof(_a, _a_p, _b, _b_p, _c, _c_p, _h, _k, _input), "Proof not valid!");
        
        sender.a = _a;
        sender.a_p = _a_p;
        sender.b = _b;
        sender.b_p = _b_p;
        sender.c = _c;
        sender.c_p = _c_p;
        sender.h = _h;
        sender.k = _k;
        sender.input = _input;
        sender.voted = true;
        
        realVoterArray.push(sender);
        realVoters[msg.sender] = realVoterArray.length - 1;
        
        voteProofs++;
    }
    
    function getVoteAnswers(uint index) view public returns(bytes[] memory, bytes[] memory, bytes[] memory) {
        return (votesArray[index].answersQuestion1, 
                votesArray[index].answersQuestion2,
                votesArray[index].answersQuestion3);
    }

    function getFakeVotersSize() view public returns(uint) {
        return fakeVoterArray.length;
    }
}