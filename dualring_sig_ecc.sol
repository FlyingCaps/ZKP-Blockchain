pragma solidity 0.8.0;

// import "@openzeppelin/contracts/utils/Arrays.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "elliptic-curve-solidity/contracts/EllipticCurve.sol";

contract DualRing {
    // using Arrays for uint256[];
    using Counters for Counters.Counter;

    // Define elliptic curve parameters
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;



    function derivePubKey(uint256 privKey) internal pure returns(uint256 qx, uint256 qy) {
        (qx, qy) = EllipticCurve.ecMul(
        privKey,
        GX,
        GY,
        AA,
        PP
        );
    }

    function mul(uint256 x, uint256 y, uint256 val) pure internal returns (uint256 qx, uint256 qy)
    {
        (qx, qy) = EllipticCurve.ecMul(
        val,
        x,
        y,
        AA,
        PP
        );
    }

    function invMod(uint256 val, uint256 p) pure internal returns (uint256)
    {
        return EllipticCurve.invMod(val,p);
    }

    function expMod(uint256 val, uint256 e, uint256 p) pure internal returns (uint256)
    {
        return EllipticCurve.expMod(val,e,p);
    }


    function getY(uint8 prefix, uint256 x) pure internal returns (uint256)
    {
        return EllipticCurve.deriveY(prefix,x,AA,BB,PP);
    }


    function onCurve(uint256 x, uint256 y) pure internal returns (bool)
    {
        return EllipticCurve.isOnCurve(x,y,AA,BB,PP);
    }

    function inverse(uint256 x, uint256 y) pure internal returns (uint256, 
    uint256) {
        return EllipticCurve.ecInv(x,y,PP);
    }

    function subtract(uint256 x1, uint256 y1,uint256 x2, uint256 y2 ) pure internal returns (uint256, 
    uint256) {
        return EllipticCurve.ecSub(x1,y1,x2,y2,AA,PP);
    }

    function add(uint256 x1, uint256 y1,uint256 x2, uint256 y2 ) pure internal returns (uint256, 
    uint256) {
        return EllipticCurve.ecAdd(x1,y1,x2,y2,AA,PP);
    }

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
    PrivateKey[] public privateKeys;

    // Constructor to initialize the contract with public keys
    constructor(uint _ring_size) {
        require(_ring_size >= 2, "DualRing: At least two public keys are required");
        generateKeys(_ring_size);
        
        
    }

    // Function to generate a new private key
    function generateKeys(uint _ring_size) public {
        for (uint256 i = 0; i < _ring_size; i++) {
            PrivateKey memory privateKey = PrivateKey({
                k: uint256(keccak256(abi.encodePacked( _privateKeyNonce.current())))
            });
            _privateKeyNonce.increment();
            uint256 _x;
            uint256 _y;
            (_x,_y) = derivePubKey(privateKey.k);
            PublicKey memory publicKey= PublicKey({x:_x, y:_y});
            publicKeys.push(publicKey);
            privateKeys.push(privateKey);
        }
        
    }

    function packArray(PublicKey[] memory arr) internal pure returns (bytes memory) {
        bytes memory packed;
        for (uint256 i = 0; i < arr.length; i++) {
            bytes memory temp = abi.encodePacked(arr[i].x, arr[i].y);
            packed = abi.encodePacked(packed, temp);
        }
        return packed;
    }

    // Function to sign a message using a private key
    function sign(string memory _message, uint256 _privateKeyIndex) public view returns (Signature memory) {
        require(_privateKeyIndex < privateKeys.length, "DualRing: Invalid private key index");
        uint256 r = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, _privateKeyIndex))) % PP;
        uint256[] memory cArray = new uint256[](publicKeys.length);
        
        uint256 sumExceptJ = 0;
        uint256 tempX = 0;
        uint256 tempY = 0;
        (tempX,tempY) =  derivePubKey(r);

        for (uint256 i = 0; i < publicKeys.length; i++) {
            if (i != _privateKeyIndex) {
                
                uint256 tempC = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, i))) % PP;
                cArray[i] = tempC;
                sumExceptJ = sumExceptJ+tempC;
                (uint256 a,uint256 b) = mul(publicKeys[i].x,publicKeys[i].y,tempC);
                (tempX,tempY) = add(a,b,tempX,tempY);


            }
        }
        
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(bytes(_message))));
        uint256 c = uint256(keccak256(abi.encodePacked(messageHash,packArray(publicKeys),tempX,tempY)));
        cArray[_privateKeyIndex] = c-sumExceptJ%PP;
        uint256 z = r - (c*privateKeys[_privateKeyIndex].k) %PP;

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
        uint256 tempX = 0;
        uint256 tempY = 0;
        uint256 sumExceptJ = 0;
        (tempX,tempY) =  derivePubKey(z);
        for (uint256 i = 0; i < publicKeys.length; i++) {
            sumExceptJ = sumExceptJ+cArray[i];
            (uint256 a,uint256 b) = mul(publicKeys[i].x,publicKeys[i].y,cArray[i]);
            (tempX,tempY) = add(a,b,tempX,tempY);


            
        }

        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(bytes(_message))));
        uint256 c = uint256(keccak256(abi.encodePacked(messageHash, packArray(publicKeys), tempX,tempY)));


        return c == sumExceptJ%PP;
    }
}

