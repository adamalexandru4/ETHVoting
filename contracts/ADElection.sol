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
    
    function addFakeVoter(address _address, bytes memory _pubKeyToRecover, bytes32 _pubKeyHash) public returns(bool) {
        // restrict to authorities
        FakeVoter memory newFakeVoter = FakeVoter(_address, _pubKeyToRecover, _pubKeyHash, true, false);
        fakeVoterArray.push(newFakeVoter);
        
        fakeVoters[_address] = fakeVoterArray.length - 1;
        votersCount++;
        
        return true;
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
    
    function getVoteAnswers(uint index) view public returns(bytes[] memory, bytes[] memory, bytes[] memory) {
        return (votesArray[index].answersQuestion1, 
                votesArray[index].answersQuestion2,
                votesArray[index].answersQuestion3);
    }
}