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

    struct Ring {
        PublicKey[] publicKeys;
        uint256 l;
        uint256 q;
    }

    function sign(bytes32 message, Ring memory ring, uint256 z) public returns (Signature memory) {
        uint256 n = ring.publicKeys.length;

        uint256 p = permut(message);
        uint256[] memory s = new uint256[](n);

        uint256 u = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
        uint256 c = u;
        uint256 v = E(u, p, ring.q);

        for (uint256 i = (z + 1) % n; i != z; i = (i + 1) % n) {
            s[i] = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
            uint256 e = g(s[i], ring.publicKeys[i].e, ring.publicKeys[i].n, p, ring.l);
            v = E(v ^ e, p, ring.q);
            if ((i + 1) % n == z) {
                c = v;
            }
        }

        s[z] = g(v ^ u, ring.publicKeys[z].e, ring.publicKeys[z].n, p, ring.l);
        Signature memory signature = Signature(bytes32(c), s);
        return signature;
    }

    function verify(bytes32 message, Signature memory signature, Ring memory ring) public view returns (bool) {
        uint256 n = ring.publicKeys.length;

        uint256 p = permut(message);
        uint256[] memory y = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            y[i] = g(signature.s[i], ring.publicKeys[i].e, ring.publicKeys[i].n, p, ring.l);
        }

        uint256 v =uint256(signature.c);
        for (uint256 i = 0; i < n; i++) {
            v = E(v ^ y[i], p, ring.q);
        }

        return v == uint256(signature.c >> 0);
    }

    function permut(bytes32 m) internal pure returns (uint256) {
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
}