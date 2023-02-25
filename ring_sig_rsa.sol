pragma solidity ^0.8.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.3.0/contracts/utils/cryptography/ECDSA.sol";

contract RingSignature {
    using ECDSA for bytes32;

    struct PublicKey {
        uint256 e;
        uint256 n;
    }

    struct Signature {
        bytes32 c;
        uint256[] s;
    }


    PublicKey[] publicKeys;
    uint256 l;
    uint256 q;

    Signature  public sig;
    


    // constructor() public {
    //     ring = generateRing(4);
    // }

    function sign(string memory message,  uint256 z) public  {
        uint256 n = publicKeys.length;

        uint256 p = permut(message);
        uint256[] memory s = new uint256[](n);

        uint256 u = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
        uint256 c = u;
        uint256 v = E(u, p, q);

        for (uint256 i = (z + 1) % n; i != z; i = (i + 1) % n) {
            s[i] = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
            uint256 e = g(s[i], publicKeys[i].e, publicKeys[i].n, p, l);
            v = E(v ^ e, p, q);
            if ((i + 1) % n == z) {
                c = v;
            }
        }

        s[z] = g(v ^ u, publicKeys[z].e, publicKeys[z].n, p, l);
        Signature memory signature = Signature(bytes32(c), s);
        sig = signature;
    }

    function verify(string memory message) public view returns (bool) {
        uint256 n = publicKeys.length;

        uint256 p = permut(message);
        uint256[] memory y = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            y[i] = g(sig.s[i], publicKeys[i].e, publicKeys[i].n, p, l);
        }

        uint256 v =uint256(sig.c);
        for (uint256 i = 0; i < n; i++) {
            v = E(v ^ y[i], p, q);
        }

        return v == uint256(sig.c >> 0);
    }

    function permut(string memory m) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(m)));
    }

    function E(uint256 x, uint256 p, uint256 q) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(x, p))) % q;
    }

    function g(uint256 x, uint256 e, uint256 n, uint256 p, uint256 l) internal pure returns (uint256) {
        (uint256 q, uint256 r) = divmod(x, n);
        uint256 rslt;
        if ((q + 1) * n <= (1 << l) - 1) {
            rslt = q * n + modExp(r, e, n);
        } else {
            rslt = x;
        }
        return rslt;
    }   
    function modExp(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256) {
        uint256 result = 1;
        while (exponent > 0) {
            if (exponent & 1 == 1) {
                result = mulmod(result, base, modulus);
            }
            base = mulmod(base, base, modulus);
            exponent >>= 1;
        }
        return result;
    }

    function divmod(uint256 a, uint256 b) internal pure returns (uint256, uint256) {
        uint256 q = a / b;
        uint256 r = a % b;
        return (q, r);
    }

    function generateRing(uint256 size) public {

        PublicKey[] memory publicKeys = new PublicKey[](size);
        for (uint256 i = 0; i < size; i++) {
            publicKeys[i] = PublicKey({
                n: 0,
                e: 0
            });
        }

        l= 1024;
        q= 1 << 255;

        // return Ring({
        //     publicKeys: publicKeys,
        //     l: 1024,
        //     q: 1 << 255
        // });
    }
}