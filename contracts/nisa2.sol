// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.0 <0.9.0;

import "./alt_bn128.sol";

// proof using recursion
contract NISA2{
	using alt_bn128 for uint256;
	using alt_bn128 for alt_bn128.G1Point;

	alt_bn128.G1Point u; // random generator

	struct Param {
		alt_bn128.G1Point[] Gs; 
		alt_bn128.G1Point P; 
		uint256 c;
	}

  struct Proof {
		alt_bn128.G1Point[] Ls;
		alt_bn128.G1Point[] Rs;
		uint256 a;
		uint256 b;
	}

  // for recursion
  struct Board {
		alt_bn128.G1Point[] Gs;
    alt_bn128.G1Point u_prime;
		uint256[] a;
		uint256[] b;
    alt_bn128.G1Point[] Ls;
		alt_bn128.G1Point[] Rs;
    uint idx;
	}

	constructor() {
		uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
		u = alt_bn128.uintToCurvePoint(seed);
	}

  /** test correctness */
  function test(uint256[] memory a) public view returns (bool) {
		Param memory param = generateParam(a);
		Proof memory p = prove(param, a);
		return verify(param, p);
	}

  /** 
    Gs : public keys
		P : prod_i (g_i ^ a_i)
		c : sum_i a_i
	 */
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

	function prove(Param memory param, uint256[] memory a) public view
	returns (Proof memory){
		require(a.length & (a.length - 1) == 0, "vector length should be a power of 2");

		uint length = log2(a.length);
		alt_bn128.G1Point[] memory Ls = new alt_bn128.G1Point[](length);
		alt_bn128.G1Point[] memory Rs = new alt_bn128.G1Point[](length);

		uint256 H_z = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(param.P), alt_bn128.serialize(u), param.c)));
		
		alt_bn128.G1Point memory u_prime = alt_bn128.mul(u, H_z);

		uint256[] memory b = new uint256[](a.length);
		for (uint i = 0; i < b.length; i++){
			b[i] = 1;
		}
		return loop(Board(param.Gs, u_prime, a, b, Ls, Rs, 0));
	}

	function loop(Board memory board) internal view returns (Proof memory){
		if (board.a.length == 1) {
			return Proof(board.Ls, board.Rs, board.a[0], board.b[0]);
		}
		alt_bn128.G1Point memory L;
		alt_bn128.G1Point memory R;
		(L, R) = LR(board.Gs, board.a, board.b, board.u_prime);
    board.Ls[board.idx] = L;
    board.Rs[board.idx] = R;

		uint256 x = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(L), alt_bn128.serialize(R))));
		uint256 x_inv = alt_bn128.inv(x);

		uint n = board.a.length / 2;
		
		alt_bn128.G1Point[] memory Gs_new = new alt_bn128.G1Point[](n);
		uint256[] memory a_new = new uint256[](n);
		uint256[] memory b_new = new uint256[](n);

		for (uint i = 0; i < n; i++){
			Gs_new[i] = alt_bn128.add(alt_bn128.mul(board.Gs[i], x_inv), alt_bn128.mul(board.Gs[n+i], x));
		  a_new[i] = alt_bn128.add(alt_bn128.mul(x, board.a[i]), alt_bn128.mul(x_inv, board.a[n+i]));
			b_new[i] = alt_bn128.add(alt_bn128.mul(x_inv, board.b[i]), alt_bn128.mul(x, board.b[n+i]));
		}
    board.Gs = Gs_new;
    board.a = a_new;
    board.b = b_new;
    board.idx += 1;
		return loop(board);
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

	function verify(Param memory param, Proof memory p) public view 
	returns (bool){
		uint256 H_z = uint256(keccak256(abi.encodePacked(alt_bn128.serialize(param.P), alt_bn128.serialize(u), param.c)));
		alt_bn128.G1Point memory P_prime = alt_bn128.add(param.P, alt_bn128.mul(u, alt_bn128.mul(param.c, H_z)));

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
					ys[i] = alt_bn128.mul(ys[i], xs[length-j-1]);
				} else {
					ys[i] = alt_bn128.mul(ys[i], xs_inv[length-j-1]);
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

  function log2(uint n) internal pure returns (uint ndigits){
		ndigits = 0;
		while (n > 1){
			ndigits += 1;
			n = n/2;
		}
	}

	function check_bit(uint i, uint j) internal pure returns (bool){
		return ((i >> j) & 1) == 1;
	}
}