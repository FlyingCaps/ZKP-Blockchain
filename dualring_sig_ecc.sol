pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Arrays.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DualRing {
    using Arrays for uint256[];
    using Counters for Counters.Counter;

    // Define elliptic curve parameters
    uint256 constant private Q = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    uint256 constant private Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
    uint256 constant private Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;

    // Define structs for public and private keys
    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    struct PrivateKey {
        uint256 k;
    }

    // Define a struct for a signature
    struct Signature {
        uint256[] c;
        uint256 z;
    }

    // Define a counter for generating private keys
    Counters.Counter private _privateKeyNonce;

    // Define arrays for public and private keys
    PublicKey[] public publicKeys;
    PrivateKey[] private privateKeys;

    // Constructor to initialize the contract with public keys
    constructor(PublicKey[] memory _publicKeys) {
        require(_publicKeys.length >= 2, "DualRing: At least two public keys are required");
        publicKeys = _publicKeys;
    }

    // Function to generate a new private key
    function generatePrivateKey() public returns (PrivateKey memory) {
        PrivateKey memory privateKey = PrivateKey({
            k: uint256(keccak256(abi.encodePacked(msg.sender, _privateKeyNonce.current())))
        });
        _privateKeyNonce.increment();
        privateKeys.push(privateKey);
        return privateKey;
    }

    // Function to sign a message using a private key
    function sign(string memory _message, uint256 _privateKeyIndex) public view returns (Signature memory) {
        require(_privateKeyIndex < privateKeys.length, "DualRing: Invalid private key index");
        uint256 r = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, _privateKeyIndex))) % Q;
        uint256[] memory cArray = new uint256[](publicKeys.length);
        uint256 sumExceptJ = 0;
        for (uint256 i = 0; i < publicKeys.length; i++) {
            if (i != _privateKeyIndex) {
                uint256 tempC = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, i))) % Q;
                cArray[i] = tempC;
                sumExceptJ = sumExceptJ.add(tempC);
            }
        }
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(bytes(_message))));
        uint256 c = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, publicKeys[Arrays.findIndex(publicKeys, msg.sender)].x, publicKeys[Arrays.findIndex(publicKeys, msg.sender)].y, Gx, Gy, r, publicKeys, messageHash))) % Q;
        cArray[_privateKeyIndex] = c.sub(sumExceptJ).mod(Q);
        uint256 z = (r.sub(cArray[_privateKeyIndex].mul(privateKeys[_privateKeyIndex].k)).mod(Q));
        Signature memory signature = Signature({
            c: cArray,
            z: z
        });
        return signature;
    }

    // Function to verify a signature

    function verify(string memory _message, Signature memory _signature) public view returns (bool) {
        uint256[] memory cArray = _signature.c;
        uint256 z = _signature.z;
        uint256 sumC = 0;
        uint256 signerIndex;
        for (uint256 i = 0; i < publicKeys.length; i++) {
            if (publicKeys[i].x == msg.sender) {
                signerIndex = i;
            }
            sumC = sumC.add(cArray[i]);
        }
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(bytes(_message))));
        uint256 c = uint256(keccak256(abi.encodePacked(publicKeys[signerIndex].x, publicKeys[signerIndex].y, Gx, Gy, g.mul(z).add(publicKeys[signerIndex].mul(cArray[signerIndex])), publicKeys, messageHash))) % Q;
        return c == sumC.mod(Q);
    }
}

