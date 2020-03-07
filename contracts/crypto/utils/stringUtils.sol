pragma solidity 0.5.16;

library StringUtils{
  function uintToString(uint v) public returns (string memory str) {
    uint maxlength = 78;
    bytes memory reversed = new bytes(maxlength);
    uint i = 0;
    while (v != 0) {
      uint remainder = v % 10;
      v = v / 10;
      reversed[i++] = byte(uint8(48 + remainder));
    }
    bytes memory s = new bytes(i);
    for (uint j = 0; j < i; j++) {
      s[j] = reversed[i - 1 - j];
    }
    str = string(s);
    return str;
  }
  
}