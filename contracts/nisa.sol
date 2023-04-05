// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.0 <0.9.0;

import "./alt_bn128.sol";

contract NISA{
	using alt_bn128 for uint256;
	using alt_bn128 for alt_bn128.G1Point;

	struct Proof {
		alt_bn128.G1Point[] Ls;
		alt_bn128.G1Point[] Rs;
		uint256 a;
		uint256 b;
	}

	alt_bn128.G1Point u; // random generator
	struct Param {
		alt_bn128.G1Point[] Gs; 
		alt_bn128.G1Point P; 
		uint256 c;
	}
	struct Var {
		alt_bn128.G1Point[] Ls;
		alt_bn128.G1Point[] Rs;
	}

	constructor() {
		uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
		u = alt_bn128.uintToCurvePoint(seed);
	}

	/** generate public keys or curve points */
	// function generate(uint count) internal view returns (alt_bn128.G1Point[] memory Gs){
	// 	Gs = new alt_bn128.G1Point[](count);
	// 	for (uint256 i = 0; i < count; i++){
	// 		Gs[i] = alt_bn128.uintToCurvePoint(i+2);
	// 	}
	// }

	function generateParam(uint256[] memory a) public view returns (Param memory param){
		require(a.length & (a.length - 1) == 0, "vector length should be a power of 2");
		param.Gs = new alt_bn128.G1Point[](a.length);
		for (uint256 i = 0; i < a.length; i++){
			param.Gs[i] = alt_bn128.uintToCurvePoint(i+2);
		}
		param.c = a[0];
		param.P = alt_bn128.mul(param.Gs[0], a[0]);
		for (uint i = 1; i < a.length; i++){
			param.c = alt_bn128.add(param.c, a[i]);
			param.P = alt_bn128.add(param.P, alt_bn128.mul(param.Gs[i], a[i]));
		}
	}

	function log2(uint n) public pure returns (uint ndigits){
		ndigits = 0;
		while (n > 1){
			ndigits += 1;
			n = n/2;
		}
	}

	function test(uint256[] memory a) public returns (Proof memory) {
		Param memory param = generateParam(a);
		Param memory sec = generateParam(a); // second copy
		Proof memory p = prove(param, a);
		// return verify(sec, p);
		return p;
	}

	function test2(uint256[] memory a) public returns (bool) {
		Param memory param = generateParam(a);
		// Param memory sec = generateParam(a); // second copy
		Proof memory p = prove(param, a);
		return verify(param, p);
	}

	/** Gs : public keys
		P : prod_i (g_i ^ a_i)
		c : sum_i a_i
	 */
	function prove(Param memory param, uint256[] memory a) public
	returns (Proof memory p){
		require(a.length & (a.length - 1) == 0, "vector length should be a power of 2");

		uint length = log2(a.length);
		Var memory v;
		v.Ls = new alt_bn128.G1Point[](length);
		v.Rs = new alt_bn128.G1Point[](length);

		uint256 H_z = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(param.P), alt_bn128.serialize(u), param.c)));
		
		alt_bn128.G1Point memory u_prime = alt_bn128.mul(u, H_z);

		uint256[] memory b = new uint256[](a.length);
		alt_bn128.G1Point[] memory Gs = new alt_bn128.G1Point[](a.length);
		for (uint i = 0; i < b.length; i++){
			b[i] = 1;
			Gs[i] = param.Gs[i];
		}
		alt_bn128.G1Point memory L;
		alt_bn128.G1Point memory R;
		uint256 x;

		// O(logn) loop
		for (uint idx = 0; idx < length; idx++){

			// L && R
			(L, R) = LR(Gs, a, b, u_prime);
			v.Ls[idx] = L; v.Rs[idx] = R;

			x = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(L), alt_bn128.serialize(R))));

			// half size
			(Gs, a, b) = nextRound(Gs, a, b, x);
		}

		p = Proof(v.Ls, v.Rs, a[0], b[0]);
	}

	function LR(alt_bn128.G1Point[] memory Gs, uint256[] memory a, uint256[] memory b, alt_bn128.G1Point memory u_prime) internal view 
	returns (alt_bn128.G1Point memory L, alt_bn128.G1Point memory R) {
		uint n = a.length / 2;
		uint256 cL = alt_bn128.mul(a[0], b[n]);
		uint256 cR = alt_bn128.mul(a[n], b[0]);
		for (uint i = 1; i < n; i++){
			cL = alt_bn128.add(cL, alt_bn128.mul(a[i], b[n+i]));
			cR = alt_bn128.add(cR, alt_bn128.mul(a[n+i], b[i]));
		}

		L = alt_bn128.mul(u_prime, cL);
		R = alt_bn128.mul(u_prime, cR);

		for (uint i = 0; i < n; i++){
			L = alt_bn128.add(L, alt_bn128.mul(Gs[n+i], a[i]));
			R = alt_bn128.add(R, alt_bn128.mul(Gs[i], a[n+i]));
		}
	}

	function nextRound(alt_bn128.G1Point[] memory Gs, uint256[] memory a, uint256[] memory b, uint256 x) internal view returns (alt_bn128.G1Point[] memory Gs_new, uint256[] memory a_new, uint256[] memory b_new)
	{
		uint n = a.length / 2;

		uint256 x_inv = alt_bn128.inv(x);

		Gs_new = new alt_bn128.G1Point[](n);
		a_new = new uint256[](n);
		b_new = new uint256[](n);

		for (uint i = 0; i < n; i++){
			Gs_new[i] = alt_bn128.add(alt_bn128.mul(Gs[i], x_inv), alt_bn128.mul(Gs[n+i], x));
			a_new[i] = alt_bn128.add(alt_bn128.mul(x, a[i]), alt_bn128.mul(x_inv, a[n+i]));
			b_new[i] = alt_bn128.add(alt_bn128.mul(x_inv, b[i]), alt_bn128.mul(x, b[n+i]));
		}
	}

	function verify(Param memory param, Proof memory p) public view 
	returns (bool){
		uint256 H_z = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(param.P), alt_bn128.serialize(u), param.c)));

		alt_bn128.G1Point memory u_prime = alt_bn128.mul(u, H_z);
		
		alt_bn128.G1Point memory P_prime = alt_bn128.add(param.P, alt_bn128.mul(u_prime, param.c));

		uint length = log2(param.Gs.length);

		uint256[] memory xs = new uint256[](length);
		uint256[] memory xs_inv = new uint256[](length);
		uint256[] memory ys = new uint256[](param.Gs.length);

		for (uint i = 0; i < length; i++){
			xs[i] = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(p.Ls[i]), alt_bn128.serialize(p.Rs[i]))));
			xs_inv[i] = alt_bn128.inv(xs[i]);
		}

		for (uint i = 0; i < param.Gs.length; i++){
			ys[i] = 1;
			for (uint j = 0; j < length; j++){
				if (check_bit(i, j)){
					ys[i] = alt_bn128.mul(ys[i], xs[j]);
				} else {
					ys[i] = alt_bn128.mul(ys[i], xs_inv[j]);
				}
			}
		}

		// verify
		alt_bn128.G1Point memory left_point;
		alt_bn128.G1Point memory right_point;

		left_point = P_prime;
		for (uint i = 0; i < length; i++){
			left_point = alt_bn128.add(left_point, 
							alt_bn128.mul(p.Ls[i], alt_bn128.mul(xs[i], xs[i]))
						);
			left_point = alt_bn128.add(left_point, 
							alt_bn128.mul(p.Rs[i], alt_bn128.mul(xs_inv[i], xs_inv[i]))
						);
		}

		right_point = alt_bn128.mul(param.Gs[0], ys[0]);
		for (uint i = 1; i < param.Gs.length; i++){
			right_point = alt_bn128.add(right_point, alt_bn128.mul(param.Gs[i], ys[i]));
		}
		right_point = alt_bn128.add(right_point, alt_bn128.mul(alt_bn128.mul(u, H_z), p.b));
		right_point = alt_bn128.mul(right_point, p.a);

		return alt_bn128.eq(left_point, right_point);
	}

	function check_bit(uint i, uint j) internal pure returns (bool){
		return ((i >> j) & 1) == 1;
	}
}