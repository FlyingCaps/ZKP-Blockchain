// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.0 <0.9.0;

// import "@openzeppelin/contracts/utils/Arrays.sol";
// import "@openzeppelin/contracts/utils/Counters.sol";
// import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// import "elliptic-curve-solidity/contracts/EllipticCurve.sol";

contract DualRingEcc {
    // using Arrays for uint256[];
    // using Counters for Counters.Counter;

    // Define elliptic curve parameters
    uint256 constant GX = 9727523064272218541460723335320998459488975639302513747055235660443850046724;
    uint256 constant GY = 5031696974169251245229961296941447383441169981934237515842977230762345915487;
    uint256 constant AA = 0;
    uint256 constant BB = 7;
    uint256 constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    
    

    // Define structs for public and private keys

    //  function multiply(Point memory p, uint256 k)
    //     public
    //     returns (Point memory)
    // {
    //     uint256[3] memory input;
    //     input[0] = p.x;
    //     input[1] = p.y;
    //     input[2] = k;

    //     bool success;
    //     uint256[2] memory result;

    //     assembly {
    //         success := call(not(0), 0x07, 0, input, 96, result, 64)
    //     }
    //     require(success, "elliptic curve multiplication failed");

    //     return Point(result[0], result[1]);
    // }

    // function add(Point memory p1, Point memory p2)
    //     internal
    //     returns (Point memory)
    // {
    //     uint256[4] memory input;
    //     input[0] = p1.x;
    //     input[1] = p1.y;
    //     input[2] = p2.x;
    //     input[3] = p2.y;

    //     bool success;
    //     uint256[2] memory result;
    //     assembly {
    //         success := call(not(0), 0x06, 0, input, 128, result, 64)
    //     }

    //     require(success, "bn256 addition failed");
    //     return Point(result[0], result[1]);
    // }

    // function sub(Point memory p1, Point memory p2)
    //     public
    //     returns (Point memory)
    // {
    //     uint256[4] memory input;
    //     input[0] = p1.x;
    //     input[1] = p1.y;
    //     input[2] = p2.x;
    //     input[3] = PP - p2.y;

    //     bool success;
    //     uint256[2] memory result;
    //     assembly {
    //         success := call(not(0), 0x06, 0, input, 128, result, 64)
    //     }

    //     require(success, "bn256 subtraction failed");
    //     return Point(result[0], result[1]);
    // }

    struct Point {
        uint256 x;
        uint256 y;
    }


    // struct PrivateKey {
    //     uint256 k;
    // }

    // Define a struct for a signature
    struct Signature {
        uint256[] c;
        uint256 z;
    }

    // Point G = Point({ x : GX , y : GY});

    // Define a counter for generating private keys
    // Counters.Counter private _privateKeyNonce;

    // Define arrays for public and private keys
    Point[] public publicKeys;
    // PrivateKey[] public privateKeys;

    uint256[] public sks;

    Signature public sig;

    // Constructor to initialize the contract with public keys
    // constructor(uint _ring_size) {
    //     require(_ring_size >= 2, "DualRing: At least two public keys are required");
    //     generateKeys(2);
        
        
    // }

    // Function to generate a new private key
    function generateKeys(uint _ring_size) public {
        for (uint i = 0; i < _ring_size; i++) {
            // PrivateKey memory privateKey = PrivateKey({
            //     k: uint256(keccak256(abi.encodePacked( block.timestamp)))
            //     // k: 2
            // });
            // uint256 _x;
            // uint256 _y;
            // Point memory pk = multiply(G, privateKey.k);
            // uint k = uint256(keccak256(abi.encodePacked( block.timestamp)));
            uint k =i;
            sks.push(k);

            uint256[3] memory input;
            input[0] = GX;
            input[1] = GY;
            input[2] = k;

            bool success;
            uint256[2] memory result;

            assembly {
                success := call(not(0), 0x07, 0, input, 96, result, 64)
                switch success case 0 { revert(0, 0) }
            }

            Point memory pk = Point(result[0], result[1]);

            publicKeys.push(pk);
            
        }
        
    }

    function packArray(Point[] memory arr) internal pure returns (bytes memory) {
        bytes memory packed;
        for (uint256 i = 0; i < arr.length; i++) {
            bytes memory temp = abi.encodePacked(arr[i].x, arr[i].y);
            packed = abi.encodePacked(packed, temp);
        }
        return packed;
    }

    // Function to sign a message using a private key
    function sign(string memory _message, uint _privateKeyIndex) public returns (Signature memory) {
        require(_privateKeyIndex < sks.length, "DualRing: Invalid private key index");
        uint256 r = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, _privateKeyIndex))) % PP;
        uint256[] memory cArray = new uint256[](publicKeys.length);
        
        uint256 sumExceptJ = 0;
        // uint256 tempX = 0;
        // uint256 tempY = 0;
        // (tempX,tempY) =  derivePubKey(r);
        // Point memory R = multiply(G, r);


         uint256[3] memory input;
            input[0] = GX;
            input[1] = GY;
            input[2] = r;

        bool success;
        uint256[2] memory R;

        assembly {
                success := call(not(0), 0x07, 0, input, 96, R, 64)
                switch success case 0 { revert(0, 0) }
        }
        

        for (uint256 i = 0; i < publicKeys.length; i++) {
            if (i != _privateKeyIndex) {
                
                cArray[i] = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, i))) % PP;
         
                uint256[2] memory temp;

                uint256[3] memory inputM;
                inputM[0] = publicKeys[i].x;
                inputM[1] = publicKeys[i].y;
                inputM[2] = cArray[i];

                assembly {
                success := call(not(0), 0x07, 0, inputM, 96, temp, 64)
                switch success case 0 { revert(0, 0) }
                }

                // Point memory tempP = multiply(publicKeys[i], tempC);

                uint256[4] memory inputA;
                inputA[0] = publicKeys[i].x;
                inputA[1] = publicKeys[i].y;
                inputA[2] = temp[0];
                inputA[3] = temp[1];

                bool success;
                // uint256[2] memory result;
                assembly {
                    success := call(not(0), 0x06, 0, inputA, 128, R, 64)
                    switch success case 0 { revert(0, 0) }
                }

                // R = add(R, tempP);


            }
        }
        
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(bytes(_message))));

        uint256 c = uint256(keccak256(abi.encodePacked(messageHash,packArray(publicKeys),R[0],R[1])));
        cArray[_privateKeyIndex] = c-sumExceptJ%PP;
        uint256 z = r - (c*sks[_privateKeyIndex]) %PP;

        Signature memory signature = Signature({
            c: cArray,
            z: z
        });

        sig = signature;
        return signature;
    }

    // Function to verify a signature

    function verify(string memory _message) public returns (bool) {

        uint256[] memory cArray = sig.c;
        uint256 z = sig.z;
        // uint256 tempX = 0;
        // uint256 tempY = 0;
        uint256 sumExceptJ = 0;
        // (tempX,tempY) =  derivePubKey(z);

        // Point memory R = multiply(G, z);
        uint256[3] memory input;
            input[0] = GX;
            input[1] = GY;
            input[2] = z;

        bool success;
        uint256[2] memory R;

        assembly {
                success := call(not(0), 0x07, 0, input, 96, R, 64)
                switch success case 0 { revert(0, 0) }
        }

        for (uint256 i = 0; i < publicKeys.length; i++) {
            sumExceptJ = sumExceptJ+cArray[i];
            // (uint256 a,uint256 b) = mul(publicKeys[i].x,publicKeys[i].y,cArray[i]);
                uint256[2] memory temp;

                uint256[3] memory inputM;
                inputM[0] = publicKeys[i].x;
                inputM[1] = publicKeys[i].y;
                inputM[2] = cArray[i];

                assembly {
                success := call(not(0), 0x07, 0, inputM, 96, temp, 64)
                switch success case 0 { revert(0, 0) }
                }
            // Point memory tempP = multiply(publicKeys[i],cArray[i]); 
                uint256[4] memory inputA;
                inputA[0] = publicKeys[i].x;
                inputA[1] = publicKeys[i].y;
                inputA[2] = R[0];
                inputA[3] = R[1];

                bool success;
                // uint256[2] memory result;
                assembly {
                    success := call(not(0), 0x06, 0, inputA, 128, R, 64)
                    switch success case 0 { revert(0, 0) }
                }


            // R = add(tempP, R);


            
        }

        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(bytes(_message))));
        uint256 c = uint256(keccak256(abi.encodePacked(messageHash, packArray(publicKeys), R[0],R[1])));


        return c == sumExceptJ%PP;
    }


}