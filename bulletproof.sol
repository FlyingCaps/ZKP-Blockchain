// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.0 <0.9.0;

import "./alt_bn128.sol";

contract BulletProof {
    using alt_bn128 for uint256;

    struct Proof {
        alt_bn128.G1Point[] Ls;
        alt_bn128.G1Point[] Rs;
        uint256 final_co;
    }
    
    /** Base points of the elliptic curve */
    function generators(uint count) public view returns (alt_bn128.G1Point[] memory Gs){
        Gs = new alt_bn128.G1Point[](count);
        for (uint i = 0; i < count; i++){
            Gs[i] = alt_bn128.uintToCurvePoint(i);
        }
        return Gs;
    }

    // /** Commitment to polynomial (lower and upper half scheme) */
    // function commit(alt_bn128.G1Point[] memory Gs, uint256[] memory poly, uint Gstart, uint polystart, uint number)
    // public view returns (alt_bn128.G1Point memory C){
    //     C = alt_bn128.mul(Gs[Gstart], poly[polystart]);
    //     for (uint i = 1; i < number; i++){
    //         C = alt_bn128.add(alt_bn128.mul(Gs[Gstart+i], poly[polystart+i]));
    //     }
    // }

    /** Commitment to polynomial (even and odd scheme) */
    function commit(alt_bn128.G1Point[] memory Gs, uint256[] memory poly) public view 
    returns (alt_bn128.G1Point memory C){
        C = alt_bn128.mul(Gs[0], poly[0]);
        for (uint i = 1; i < poly.length; i++){
            C = alt_bn128.add(alt_bn128.mul(Gs[i], poly[i]), C);
        }
    }

    function splitEvenOdd(alt_bn128.G1Point[] memory Gs, uint256[] memory poly) public pure 
    returns (alt_bn128.G1Point[] memory Gs_even, alt_bn128.G1Point[] memory Gs_odd, uint256[] memory poly_even, uint256[] memory poly_odd){
        uint length = poly.length / 2;

        Gs_even = new alt_bn128.G1Point[](length);
        Gs_odd = new alt_bn128.G1Point[](length);
        poly_even = new uint256[](length);
        poly_odd = new uint256[](length);

        for (uint i = 0; i < length; i++){
            Gs_odd[i] = Gs[2*i+1];
            Gs_even[i] = Gs[2*i];
            poly_odd[i] = poly[2*i+1];
            poly_even[i] = poly[2*i];
        }
    }

    /** new base points and polynomial 
     * G'_i = aG_2i + G_(2i+1)
     * c'_i = c_2i + ac_(2i+1)
     * => intermediate commitment 
     * C' = sum c'_i G'_i = aC + a^2L + R
    */
    function nextRound(alt_bn128.G1Point[] memory Gs, uint256[] memory poly , uint256 a) public view
    returns (alt_bn128.G1Point[] memory Gs_new, uint256[] memory poly_new){
        uint length = poly.length / 2;

        Gs_new = new alt_bn128.G1Point[](length);
        poly_new = new uint256[](length);

        for (uint i = 0; i < length; i++){
            Gs_new[i] = alt_bn128.add(alt_bn128.mul(Gs[2*i], a), Gs[2*i+1]);
            poly_new[i] = alt_bn128.add(poly_new[2*i], alt_bn128.mul(a, poly_new[2*i+1]));
        }
    }

    function log2(uint n) public pure returns (uint ndigits){
        ndigits = 0;
        while (n > 1){
            ndigits += 1;
            n <<= 1;
        }
    }

    function nextRound(alt_bn128.G1Point[] memory Gs, uint256 a) public view
    returns (alt_bn128.G1Point[] memory Gs_new){
        uint length = Gs.length / 2;

        Gs_new = new alt_bn128.G1Point[](length);
        for (uint i = 0; i < length; i++){
            Gs_new[i] = alt_bn128.add(alt_bn128.mul(Gs[2*i], a), Gs[2*i+1]);
        }
    }

    /** Proof of the polynomial */
    function prove(alt_bn128.G1Point[] memory Gs, alt_bn128.G1Point memory C, uint256[] memory poly) public view
    returns (Proof memory p) {
        require(poly.length & (poly.length - 1) == 0, "polynomial length should be a power of 2");
        uint length = log2(poly.length);

        // Fiat-shamir heuristics as challenge
        uint256 a;
        bytes32 r = alt_bn128.serialize(C);

        alt_bn128.G1Point[] memory Gs_even;
        alt_bn128.G1Point[] memory Gs_odd;
        uint256[] memory poly_even;
        uint256[] memory poly_odd;

        alt_bn128.G1Point memory L;
        alt_bn128.G1Point memory R;

        alt_bn128.G1Point[] memory Ls = new alt_bn128.G1Point[](length);
        alt_bn128.G1Point[] memory Rs = new alt_bn128.G1Point[](length);

        // log(n) rounds
        for (uint i = 0; i < length; i++){
            (Gs_even, Gs_odd, poly_even, poly_odd) = splitEvenOdd(Gs, poly);

            L = commit(Gs_even, poly_odd); Ls[i] = L;
            R = commit(Gs_odd, poly_even); Rs[i] = R;

            r = keccak256(abi.encodePacked(r, alt_bn128.serialize(L), alt_bn128.serialize(R)));
            a = alt_bn128.mod(uint256(r));

            // Generate half-size poly and Gs
            (Gs, poly) = nextRound(Gs, poly, a);
        }

        p = Proof(Ls, Rs, poly[0]);
    }

    /** Base case check: final point * final coefficient ?= final commitment */
    function verify(alt_bn128.G1Point[] memory Gs, alt_bn128.G1Point memory C, Proof memory p) public view
    returns (bool){
        // Fiat-shamir heuristics
        uint256 a;
        bytes32 r = alt_bn128.serialize(C);

        for (uint i = 0; i < p.Ls.length; i++){
            r = keccak256(abi.encodePacked(r, alt_bn128.serialize(p.Ls[i]), alt_bn128.serialize(p.Rs[i])));
            a = alt_bn128.mod(uint256(r));

            // C' = sum c'_i G'_i = aC + a^2L + R
            C = alt_bn128.add(
                    alt_bn128.add(
                        alt_bn128.mul(C, a), 
                        alt_bn128.mul(p.Ls[i], a*a)
                    ), 
                    p.Rs[i]
                );

            Gs = nextRound(Gs, a);
        }
        return alt_bn128.eq(alt_bn128.mul(Gs[0], p.final_co), C);
    }

}