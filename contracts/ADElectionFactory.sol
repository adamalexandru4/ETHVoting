pragma solidity ^0.5.0;
import './ADElection.sol';

contract ADElectionFactory {
    address[] public ADElectionArray;
    
    function createADElection(string memory electionName, bytes memory encryptionPubKey, address zkVerifier) public returns (uint){
        
        ADElection newADElection = new ADElection(electionName, encryptionPubKey, zkVerifier, msg.sender);
        ADElectionArray.push(address(newADElection));
        
        // Return the number of election to channge details in future
        return ADElectionArray.length - 1; 
    }
    
    function getADElectionArray() public view returns(address[] memory) {
        return ADElectionArray; 
    }
    
    function getNoElections() public view returns(uint) {
        return ADElectionArray.length;
    }
}