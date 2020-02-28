include "../../node_modules/circomlib/circuits/comparators.circom";

template ValidateVotes(noOptionsForQ1, noOptionsForQ2, noOptionsForQ3) {
    signal input question1TotalOptions;
    signal input question2TotalOptions;
    signal input question3TotalOptions;

    signal private input question1TotalVotes;
    signal private input question2TotalVotes;
    signal private input question3TotalVotes;
    signal private input totalVotes;

    signal private input question1[noOptionsForQ1];
    signal private input question2[noOptionsForQ2];
    signal private input question3[noOptionsForQ3];

    signal private input voter;
    signal private input signature;
    signal private input p;
    signal private input rcm[2];

    signal output outQuestion2TotalVotes;
    signal output outQuestion3TotalVotes;
    signal output outQuestion1TotalVotes;
    signal output outTotalVotes;

    for(var i = 0; i < question1TotalOptions; i++) {
        if(question1[i] == 1) {
            outQuestion1TotalVotes+=1;
            outTotalVotes+=1;
            outQuestion1TotalVotes === 1; // Constraint allow just one vote
        }
    }
    
    

    for(var i = 0; i < question2TotalOptions; i++) {
        if(question2[i] == 1) {
            outQuestion2TotalVotes+=1;
            outTotalVotes+=1;
            outQuestion2TotalVotes === 1; // Constraint allow just one vote
        }
    }

    for(var i = 0; i < question3TotalOptions; i++) {
        if(question3[i] == 1) {
            outQuestion3TotalVotes+=1;
            outTotalVotes+=1;
            outQuestion3TotalVotes === 1; // Constraint allow just one vote
        }
    }

    // Check if each pool received correct input
    question1TotalVotes === 1;
    question2TotalVotes === 1;
    question3TotalVotes === 1;
    
    // Test the total votes on input and counted
    totalVotes === question1TotalVotes + question2TotalVotes + question2TotalVotes;
    outTotalVotes === outQuestion1TotalVotes + outQuestion2TotalVotes + outQuestion3TotalVotes;

    // Trick for comparing an input with an output
    // Must convert the number using this method and comparing after
    component iszA = IsZero();
    iszA.in <== totalVotes - (question1TotalVotes + question2TotalVotes + question3TotalVotes);
    iszA.out === 1;

    component iszB = IsZero();
    iszB.in <== outTotalVotes - (outQuestion1TotalVotes + outQuestion2TotalVotes + outQuestion3TotalVotes);
    iszB.out === 1;

    component isequal = IsEqual();
    isequal.in[0] <== iszA.out;
    isequal.in[1] <== iszB.out;
    isequal.out === 1;

    iszB.out === iszA.out;

    // Check if the input total candidates are aligned with the setup
    noOptionsForQ1 === question1TotalOptions;
    noOptionsForQ2 === question2TotalOptions;
    noOptionsForQ3 === question3TotalOptions;
}

component main = ValidateVotes(4, 2, 4) 