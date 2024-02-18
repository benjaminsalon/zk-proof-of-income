// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    PROOF_LEN_CPTR = 0x44;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x14c4;
    uint256 internal constant     INSTANCE_CPTR = 0x14e4;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x07e4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x08a4;

    uint256 internal constant                VK_MPTR = 0x05a0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x05a0;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x05c0;
    uint256 internal constant                 K_MPTR = 0x05e0;
    uint256 internal constant             N_INV_MPTR = 0x0600;
    uint256 internal constant             OMEGA_MPTR = 0x0620;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0640;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0660;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0680;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x06a0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x06c0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x06e0;
    uint256 internal constant              G1_X_MPTR = 0x0700;
    uint256 internal constant              G1_Y_MPTR = 0x0720;
    uint256 internal constant            G2_X_1_MPTR = 0x0740;
    uint256 internal constant            G2_X_2_MPTR = 0x0760;
    uint256 internal constant            G2_Y_1_MPTR = 0x0780;
    uint256 internal constant            G2_Y_2_MPTR = 0x07a0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x07c0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x07e0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0800;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0820;

    uint256 internal constant CHALLENGE_MPTR = 0x1380;

    uint256 internal constant THETA_MPTR = 0x1380;
    uint256 internal constant  BETA_MPTR = 0x13a0;
    uint256 internal constant GAMMA_MPTR = 0x13c0;
    uint256 internal constant     Y_MPTR = 0x13e0;
    uint256 internal constant     X_MPTR = 0x1400;
    uint256 internal constant  ZETA_MPTR = 0x1420;
    uint256 internal constant    NU_MPTR = 0x1440;
    uint256 internal constant    MU_MPTR = 0x1460;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1480;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x14a0;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x14c0;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x14e0;
    uint256 internal constant             X_N_MPTR = 0x1500;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x1520;
    uint256 internal constant          L_LAST_MPTR = 0x1540;
    uint256 internal constant         L_BLIND_MPTR = 0x1560;
    uint256 internal constant             L_0_MPTR = 0x1580;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x15a0;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x15c0;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x15e0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1600;
    uint256 internal constant          R_EVAL_MPTR = 0x1620;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1640;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x1660;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1680;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x16a0;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x05a0, 0x015ed1eb11aeda63673c5cd1d21e7576d6d9b610127552013d058798ad9942a9) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000003) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x1460, calldataload(PROOF_LEN_CPTR)))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0180) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0280) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0380) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0100) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0b60) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x05a0, 0x015ed1eb11aeda63673c5cd1d21e7576d6d9b610127552013d058798ad9942a9) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000003) // num_instances
                mstore(0x05e0, 0x0000000000000000000000000000000000000000000000000000000000000013) // k
                mstore(0x0600, 0x3064486657634403844b0eac78ca882cfd284341fcb0615a15cfcd17b14d8201) // n_inv
                mstore(0x0620, 0x0cf1526aaafac6bacbb67d11a4077806b123f767e4b0883d14cc0193568fc082) // omega
                mstore(0x0640, 0x20784546081c2aba227a9c15990bf6983ba2a2758faf563f38b437203ee230a9) // omega_inv
                mstore(0x0660, 0x230385eb1034f58ed905d7dafbbf62da84661de658f682a719d8836889e04857) // omega_inv_to_l
                mstore(0x0680, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x06a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x06c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0700, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0720, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0740, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0760, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0780, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x07a0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x07c0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x07e0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x0800, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0820, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0840, 0x0216e1962b118a871641191e5b56ef67b7234be0ba1f6e65cc3149f4cdf7d2a4) // fixed_comms[0].x
                mstore(0x0860, 0x14dcba857f39b53d46db4acec4e59ee5a328d35713fd031114b75025d1ecb3cb) // fixed_comms[0].y
                mstore(0x0880, 0x187c9b94532ab54b1021c5f2a0961ed8cc7e6c1d6fba329813fdc75e12010253) // fixed_comms[1].x
                mstore(0x08a0, 0x0b9e3099fb5fda92a6c4800600cdce14b40592756a6efc7ff6b7c4b016a2b584) // fixed_comms[1].y
                mstore(0x08c0, 0x012490bac7f67b847cf6946033db4a632d4b8c0661c116fe4fc8bc2c5377e310) // fixed_comms[2].x
                mstore(0x08e0, 0x0ce78f7694626a9f6ff31e7aae992e8ec8a9bd5fc1f25b18e3d5cf491e32022e) // fixed_comms[2].y
                mstore(0x0900, 0x0b0b730c7cc036b250580368804e6ed2056381162d89e0043b5bd98f4ee75f3a) // fixed_comms[3].x
                mstore(0x0920, 0x0ac8139daf06f5eea557c933528300d6f404d8695a11179c01e1faf1b8b3fc8e) // fixed_comms[3].y
                mstore(0x0940, 0x18bb78b97ae3439de5eb18cc8ff88b94632fd4d4a197ab1d6fbcf7cd4e208e71) // fixed_comms[4].x
                mstore(0x0960, 0x0f01ef2f892e9bed184b22e73245e666380819b1f89cdfe8d2a2725099bcc499) // fixed_comms[4].y
                mstore(0x0980, 0x07441a798ac3fd5588b3782c716810b647a50765a678f59494231a3317ef8b43) // fixed_comms[5].x
                mstore(0x09a0, 0x2f8a11be120a83d9907b9090b91a2770d3507502a11b6f928cb1720227e07cb0) // fixed_comms[5].y
                mstore(0x09c0, 0x1082dd80327937416906c49ce703e84270f642e316ea7d79764b5d0ca0c17668) // fixed_comms[6].x
                mstore(0x09e0, 0x03882a90aef5c45d429a2a7c228f67e1ef92b4053ab40ed9ccca6fba107f5a49) // fixed_comms[6].y
                mstore(0x0a00, 0x0762a792c4e078b1a1601f19012b5aa2a802c88ad53ffcd0ddffc52a18441859) // fixed_comms[7].x
                mstore(0x0a20, 0x1b8aac3ff017c6c2688fbef6532e0ada2f70d21cb8b20cf918ad75fa40c39059) // fixed_comms[7].y
                mstore(0x0a40, 0x1083e2b5a2692c9dfc6bfc36b2c062ce3e9639291634299c2454f6870edc74d4) // fixed_comms[8].x
                mstore(0x0a60, 0x113f793e266061a8372644df1b58d827cc8a67a3e5ebbacca8188d0308b3794a) // fixed_comms[8].y
                mstore(0x0a80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[9].x
                mstore(0x0aa0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[9].y
                mstore(0x0ac0, 0x2c3426f6ae01c251eb7b3ad51ac755b2248f56fa8d3eaf6a73e48b658e164514) // fixed_comms[10].x
                mstore(0x0ae0, 0x220ec25c20e22e59748822f57735d7dc10cc7bb9ff523a408d7be829a81df34a) // fixed_comms[10].y
                mstore(0x0b00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[11].x
                mstore(0x0b20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[11].y
                mstore(0x0b40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[12].x
                mstore(0x0b60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[12].y
                mstore(0x0b80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].x
                mstore(0x0ba0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].y
                mstore(0x0bc0, 0x0282ccf814185972925dc138ef87c90725017e68e61835dbf7e357bd019e111a) // fixed_comms[14].x
                mstore(0x0be0, 0x12340e976d5284a05acd024637ee9b975e1ffd4fd2687737212667d9ef059090) // fixed_comms[14].y
                mstore(0x0c00, 0x0b43a13d09f0eb73dc967846a8013d832fcb609a5fb5bfaaa59476e13003d45b) // fixed_comms[15].x
                mstore(0x0c20, 0x2cebd1042aae886ebdb5a1abbb8d07301d9c903d2c46ab07a4780b735dc9a822) // fixed_comms[15].y
                mstore(0x0c40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[16].x
                mstore(0x0c60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[16].y
                mstore(0x0c80, 0x1374c4c06b1219a9760699a85492f97a0f17ed49ddcfce2248adc9df8cb0926a) // fixed_comms[17].x
                mstore(0x0ca0, 0x2fce9e1ba999b7449ed4933ed8e2ad23d89e8e9cdde42b6e038e19d02dce3374) // fixed_comms[17].y
                mstore(0x0cc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[18].x
                mstore(0x0ce0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[18].y
                mstore(0x0d00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[19].x
                mstore(0x0d20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[19].y
                mstore(0x0d40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[20].x
                mstore(0x0d60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[20].y
                mstore(0x0d80, 0x0b5344c0f186b30f1a74579b8a4e31609a59f38cdacaedc651d3c71473d052b6) // fixed_comms[21].x
                mstore(0x0da0, 0x0b6d56d0bb6b2b32ea2dab46a3dadd9f8d8a0234edcbf7ac3cd2d532367792af) // fixed_comms[21].y
                mstore(0x0dc0, 0x0c0f1a2980e4e061ec39b173145e45ff63dac660b1f5cf6ed7980bd61d03d83c) // fixed_comms[22].x
                mstore(0x0de0, 0x2546f6b73d270a25fdac502ff2b4c7d41a6024c5ffe335f3364f4b6f16e6976d) // fixed_comms[22].y
                mstore(0x0e00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[23].x
                mstore(0x0e20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[23].y
                mstore(0x0e40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[24].x
                mstore(0x0e60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[24].y
                mstore(0x0e80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[25].x
                mstore(0x0ea0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[25].y
                mstore(0x0ec0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[26].x
                mstore(0x0ee0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[26].y
                mstore(0x0f00, 0x049df352acb3a45a7fe15558a157038d557365ff21a562a4d29b99e237818fdb) // fixed_comms[27].x
                mstore(0x0f20, 0x1e6ea4545cac489d51144bf36c369196454c8b5d5c483b90017ea64fcfe4963b) // fixed_comms[27].y
                mstore(0x0f40, 0x051699300252f4edbb6b52c8061d009f5b885dc0903500bbcfa7827a202a9d1f) // fixed_comms[28].x
                mstore(0x0f60, 0x18defa4a959b19b73fbcac2bbd4e9356c94314b19d58ea7c53bed9c25b195d9c) // fixed_comms[28].y
                mstore(0x0f80, 0x1a3f2401b386d536dc0a1ff30045d501b609cb23602eedfceef2d4264d602420) // fixed_comms[29].x
                mstore(0x0fa0, 0x1ca4d5bc2f08eb628b63bae40ea0b40e82102dfc7bad0a4b0aa92d783d22ead2) // fixed_comms[29].y
                mstore(0x0fc0, 0x1a3f2401b386d536dc0a1ff30045d501b609cb23602eedfceef2d4264d602420) // fixed_comms[30].x
                mstore(0x0fe0, 0x1ca4d5bc2f08eb628b63bae40ea0b40e82102dfc7bad0a4b0aa92d783d22ead2) // fixed_comms[30].y
                mstore(0x1000, 0x2be8e51f2c72ca2832826b7452c64cf95f1be50f91e93086e0fcf75bf15fad62) // fixed_comms[31].x
                mstore(0x1020, 0x16cb505ae9236137ce904d411d583fce2aecc38e72b10398ef4af76cd7dde018) // fixed_comms[31].y
                mstore(0x1040, 0x2be8e51f2c72ca2832826b7452c64cf95f1be50f91e93086e0fcf75bf15fad62) // fixed_comms[32].x
                mstore(0x1060, 0x16cb505ae9236137ce904d411d583fce2aecc38e72b10398ef4af76cd7dde018) // fixed_comms[32].y
                mstore(0x1080, 0x09b8d32874c3fff46fc88d2e9b56513136b556285d9a116cf88ad95081afa015) // fixed_comms[33].x
                mstore(0x10a0, 0x2ab67ed9a452a52afe519a10499f82cd0980f8fa7cd85dafe76d318bd3163beb) // fixed_comms[33].y
                mstore(0x10c0, 0x09b8d32874c3fff46fc88d2e9b56513136b556285d9a116cf88ad95081afa015) // fixed_comms[34].x
                mstore(0x10e0, 0x2ab67ed9a452a52afe519a10499f82cd0980f8fa7cd85dafe76d318bd3163beb) // fixed_comms[34].y
                mstore(0x1100, 0x2f0e4409049908c1091a4d3c59a0c816742a61b2c770d1a8caefbf68a4c68e73) // fixed_comms[35].x
                mstore(0x1120, 0x0fa4d0dfe99adba964723b4542bb0c4447a255f82d59f7d96168eaa341e0f149) // fixed_comms[35].y
                mstore(0x1140, 0x0e7fa261d2f88ea8d8e2666412fa3d3d1faa845793ddb40862e57d1c57fd0aca) // fixed_comms[36].x
                mstore(0x1160, 0x22c47c0930845a759ae2cf0397ae00991e40cf516144e0746fb4a5bd48de60d1) // fixed_comms[36].y
                mstore(0x1180, 0x044c90ab86815dccc1e3a903952d216cb666880388aeb065b0a530a840ef6fcd) // permutation_comms[0].x
                mstore(0x11a0, 0x20423a700b0e986380db464d0f9d07a6cd027421064ba401075195b75acb56b7) // permutation_comms[0].y
                mstore(0x11c0, 0x296920245ccf20b76d4e25dcae40905b9f1e66c24813b7d0a95f7961fc51b955) // permutation_comms[1].x
                mstore(0x11e0, 0x187c8c0640f7561170b45f89c46e5a6397e97d870323f38b4a4634135beaa325) // permutation_comms[1].y
                mstore(0x1200, 0x0c61dc15fb70d5a92088f46af977ae587649fa3ecfc442ebcaccf39c9ac728d5) // permutation_comms[2].x
                mstore(0x1220, 0x1a03d4641078a2d9d6f7d49430a2e37ea0796dd77fa625339ce2e85d1591de9b) // permutation_comms[2].y
                mstore(0x1240, 0x1e6f62336341d1b5b4b957d94793d6b4a7576925fc3a5282a485a4d3bc4fbcb3) // permutation_comms[3].x
                mstore(0x1260, 0x091251bea1003098fde04622b373d87834f1d06f8124a1b81ade3cf94a558cb5) // permutation_comms[3].y
                mstore(0x1280, 0x19246d84c2260d828f72e1fe7c289dfbe730959849f949d137e5ca40a3b76775) // permutation_comms[4].x
                mstore(0x12a0, 0x0136424cd2d9e208f63588e0f0e89b3818bbadb6496724321a1965df43c47b28) // permutation_comms[4].y
                mstore(0x12c0, 0x304ea1ae8077064dd78a50e5a6e79081418ba22e75cc4d5dcd075e410375c45f) // permutation_comms[5].x
                mstore(0x12e0, 0x14928efe1a73b5d3dc478d2dcf9d51ec52a8b9e52b040846a1d7fd4ec9cedf1e) // permutation_comms[5].y
                mstore(0x1300, 0x197d80284883061a16dfc9d037cc7e36f55ececbc520f89bc2f79970a81807fb) // permutation_comms[6].x
                mstore(0x1320, 0x0e2d5a3c74fcbf61e931c1c74e9b9f9ca916ced24ee34b65e7aac950933cd589) // permutation_comms[6].y
                mstore(0x1340, 0x1bb547de66663d2dc23e8269651c33fff970b1ee0ea36ec63824dce7b67f3ef9) // permutation_comms[7].x
                mstore(0x1360, 0x1b83c4ec52644683c8dc1810f8a3d83fb6b778226e127474b483349464462455) // permutation_comms[7].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let delta := 4131629893567559867359510883348571134090853742863529169391034518566172092834
                let y := mload(Y_MPTR)
                {
                    let f_12 := calldataload(0x0b44)
                    let a_4 := calldataload(0x0964)
                    let a_2 := calldataload(0x0924)
                    let var0 := sub(r, a_2)
                    let var1 := addmod(a_4, var0, r)
                    let var2 := mulmod(f_12, var1, r)
                    quotient_eval_numer := var2
                }
                {
                    let f_19 := calldataload(0x0c24)
                    let a_5 := calldataload(0x0984)
                    let a_3 := calldataload(0x0944)
                    let var0 := sub(r, a_3)
                    let var1 := addmod(a_5, var0, r)
                    let var2 := mulmod(f_19, var1, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var2, r)
                }
                {
                    let f_7 := calldataload(0x0aa4)
                    let a_4 := calldataload(0x0964)
                    let a_0 := calldataload(0x08e4)
                    let a_2 := calldataload(0x0924)
                    let var0 := addmod(a_0, a_2, r)
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_4, var1, r)
                    let var3 := mulmod(f_7, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_14 := calldataload(0x0b84)
                    let a_5 := calldataload(0x0984)
                    let a_1 := calldataload(0x0904)
                    let a_3 := calldataload(0x0944)
                    let var0 := addmod(a_1, a_3, r)
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_5, var1, r)
                    let var3 := mulmod(f_14, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_10 := calldataload(0x0b04)
                    let a_4 := calldataload(0x0964)
                    let a_0 := calldataload(0x08e4)
                    let a_2 := calldataload(0x0924)
                    let var0 := mulmod(a_0, a_2, r)
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_4, var1, r)
                    let var3 := mulmod(f_10, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_17 := calldataload(0x0be4)
                    let a_5 := calldataload(0x0984)
                    let a_1 := calldataload(0x0904)
                    let a_3 := calldataload(0x0944)
                    let var0 := mulmod(a_1, a_3, r)
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_5, var1, r)
                    let var3 := mulmod(f_17, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_8 := calldataload(0x0ac4)
                    let a_4 := calldataload(0x0964)
                    let a_0 := calldataload(0x08e4)
                    let a_2 := calldataload(0x0924)
                    let var0 := sub(r, a_2)
                    let var1 := addmod(a_0, var0, r)
                    let var2 := sub(r, var1)
                    let var3 := addmod(a_4, var2, r)
                    let var4 := mulmod(f_8, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_15 := calldataload(0x0ba4)
                    let a_5 := calldataload(0x0984)
                    let a_1 := calldataload(0x0904)
                    let a_3 := calldataload(0x0944)
                    let var0 := sub(r, a_3)
                    let var1 := addmod(a_1, var0, r)
                    let var2 := sub(r, var1)
                    let var3 := addmod(a_5, var2, r)
                    let var4 := mulmod(f_15, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_9 := calldataload(0x0ae4)
                    let a_4 := calldataload(0x0964)
                    let a_2 := calldataload(0x0924)
                    let var0 := sub(r, a_2)
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_4, var1, r)
                    let var3 := mulmod(f_9, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_16 := calldataload(0x0bc4)
                    let a_5 := calldataload(0x0984)
                    let a_3 := calldataload(0x0944)
                    let var0 := sub(r, a_3)
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_5, var1, r)
                    let var3 := mulmod(f_16, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_11 := calldataload(0x0b24)
                    let a_4 := calldataload(0x0964)
                    let var0 := mulmod(f_11, a_4, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var0, r)
                }
                {
                    let f_18 := calldataload(0x0c04)
                    let a_5 := calldataload(0x0984)
                    let var0 := mulmod(f_18, a_5, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var0, r)
                }
                {
                    let f_13 := calldataload(0x0b64)
                    let a_4 := calldataload(0x0964)
                    let var0 := 0x1
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_4, var1, r)
                    let var3 := mulmod(a_4, var2, r)
                    let var4 := mulmod(f_13, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_20 := calldataload(0x0c44)
                    let a_5 := calldataload(0x0984)
                    let var0 := 0x1
                    let var1 := sub(r, var0)
                    let var2 := addmod(a_5, var1, r)
                    let var3 := mulmod(a_5, var2, r)
                    let var4 := mulmod(f_20, var3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var4, r)
                }
                {
                    let f_22 := calldataload(0x0c84)
                    let a_4 := calldataload(0x0964)
                    let a_4_prev_1 := calldataload(0x09a4)
                    let var0 := 0x0
                    let a_0 := calldataload(0x08e4)
                    let a_2 := calldataload(0x0924)
                    let var1 := mulmod(a_0, a_2, r)
                    let var2 := addmod(var0, var1, r)
                    let a_1 := calldataload(0x0904)
                    let a_3 := calldataload(0x0944)
                    let var3 := mulmod(a_1, a_3, r)
                    let var4 := addmod(var2, var3, r)
                    let var5 := addmod(a_4_prev_1, var4, r)
                    let var6 := sub(r, var5)
                    let var7 := addmod(a_4, var6, r)
                    let var8 := mulmod(f_22, var7, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var8, r)
                }
                {
                    let f_21 := calldataload(0x0c64)
                    let a_4 := calldataload(0x0964)
                    let var0 := 0x0
                    let a_0 := calldataload(0x08e4)
                    let a_2 := calldataload(0x0924)
                    let var1 := mulmod(a_0, a_2, r)
                    let var2 := addmod(var0, var1, r)
                    let a_1 := calldataload(0x0904)
                    let a_3 := calldataload(0x0944)
                    let var3 := mulmod(a_1, a_3, r)
                    let var4 := addmod(var2, var3, r)
                    let var5 := sub(r, var4)
                    let var6 := addmod(a_4, var5, r)
                    let var7 := mulmod(f_21, var6, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var7, r)
                }
                {
                    let f_24 := calldataload(0x0cc4)
                    let a_4 := calldataload(0x0964)
                    let var0 := 0x1
                    let a_2 := calldataload(0x0924)
                    let var1 := mulmod(var0, a_2, r)
                    let a_3 := calldataload(0x0944)
                    let var2 := mulmod(var1, a_3, r)
                    let var3 := sub(r, var2)
                    let var4 := addmod(a_4, var3, r)
                    let var5 := mulmod(f_24, var4, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var5, r)
                }
                {
                    let f_23 := calldataload(0x0ca4)
                    let a_4 := calldataload(0x0964)
                    let a_4_prev_1 := calldataload(0x09a4)
                    let var0 := 0x1
                    let a_2 := calldataload(0x0924)
                    let var1 := mulmod(var0, a_2, r)
                    let a_3 := calldataload(0x0944)
                    let var2 := mulmod(var1, a_3, r)
                    let var3 := mulmod(a_4_prev_1, var2, r)
                    let var4 := sub(r, var3)
                    let var5 := addmod(a_4, var4, r)
                    let var6 := mulmod(f_23, var5, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var6, r)
                }
                {
                    let f_26 := calldataload(0x0d04)
                    let a_4 := calldataload(0x0964)
                    let var0 := 0x0
                    let a_2 := calldataload(0x0924)
                    let var1 := addmod(var0, a_2, r)
                    let a_3 := calldataload(0x0944)
                    let var2 := addmod(var1, a_3, r)
                    let var3 := sub(r, var2)
                    let var4 := addmod(a_4, var3, r)
                    let var5 := mulmod(f_26, var4, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var5, r)
                }
                {
                    let f_25 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0964)
                    let a_4_prev_1 := calldataload(0x09a4)
                    let var0 := 0x0
                    let a_2 := calldataload(0x0924)
                    let var1 := addmod(var0, a_2, r)
                    let a_3 := calldataload(0x0944)
                    let var2 := addmod(var1, a_3, r)
                    let var3 := addmod(a_4_prev_1, var2, r)
                    let var4 := sub(r, var3)
                    let var5 := addmod(a_4, var4, r)
                    let var6 := mulmod(f_25, var5, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var6, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(r, mulmod(l_0, calldataload(0x0f84), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x1044)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, r), sub(r, perm_z_last), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0fe4), sub(r, calldataload(0x0fc4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1044), sub(r, calldataload(0x1024)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0fa4)
                    let rhs := calldataload(0x0f84)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x08e4), mulmod(beta, calldataload(0x0e84), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0904), mulmod(beta, calldataload(0x0ea4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0924), mulmod(beta, calldataload(0x0ec4), r), r), gamma, r), r)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x08e4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0904), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0924), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1004)
                    let rhs := calldataload(0x0fe4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0944), mulmod(beta, calldataload(0x0ee4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0964), mulmod(beta, calldataload(0x0f04), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0984), mulmod(beta, calldataload(0x0f24), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0944), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0964), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0984), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1064)
                    let rhs := calldataload(0x1044)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x09c4), mulmod(beta, calldataload(0x0f44), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x0f64), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x09c4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r), gamma, r), r)
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1084), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1084), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_2 := calldataload(0x0a04)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_2, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_27 := calldataload(0x0d24)
                        let var0 := 0x1
                        let var1 := mulmod(f_27, var0, r)
                        let a_0 := calldataload(0x08e4)
                        let var2 := mulmod(var1, a_0, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_4 := calldataload(0x0964)
                        let var8 := mulmod(var1, a_4, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x10c4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x10a4), sub(r, calldataload(0x1084)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x10e4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x10e4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_2 := calldataload(0x0a04)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_2, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_28 := calldataload(0x0d44)
                        let var0 := 0x1
                        let var1 := mulmod(f_28, var0, r)
                        let a_1 := calldataload(0x0904)
                        let var2 := mulmod(var1, a_1, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_5 := calldataload(0x0984)
                        let var8 := mulmod(var1, a_5, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x1124), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x1104), sub(r, calldataload(0x10e4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1144), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1144), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_3 := calldataload(0x0a24)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_3, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_29 := calldataload(0x0d64)
                        let var0 := 0x1
                        let var1 := mulmod(f_29, var0, r)
                        let a_0 := calldataload(0x08e4)
                        let var2 := mulmod(var1, a_0, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_4 := calldataload(0x0964)
                        let var8 := mulmod(var1, a_4, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x1184), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x1164), sub(r, calldataload(0x1144)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x11a4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x11a4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_3 := calldataload(0x0a24)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_3, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_30 := calldataload(0x0d84)
                        let var0 := 0x1
                        let var1 := mulmod(f_30, var0, r)
                        let a_1 := calldataload(0x0904)
                        let var2 := mulmod(var1, a_1, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_5 := calldataload(0x0984)
                        let var8 := mulmod(var1, a_5, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x11e4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x11c4), sub(r, calldataload(0x11a4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1204), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1204), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_4 := calldataload(0x0a44)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_4, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_31 := calldataload(0x0da4)
                        let var0 := 0x1
                        let var1 := mulmod(f_31, var0, r)
                        let a_0 := calldataload(0x08e4)
                        let var2 := mulmod(var1, a_0, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_4 := calldataload(0x0964)
                        let var8 := mulmod(var1, a_4, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x1244), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x1224), sub(r, calldataload(0x1204)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1264), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1264), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_4 := calldataload(0x0a44)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_4, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_32 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_32, var0, r)
                        let a_1 := calldataload(0x0904)
                        let var2 := mulmod(var1, a_1, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_5 := calldataload(0x0984)
                        let var8 := mulmod(var1, a_5, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x12a4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x1284), sub(r, calldataload(0x1264)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x12c4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x12c4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_5 := calldataload(0x0a64)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_5, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_33 := calldataload(0x0de4)
                        let var0 := 0x1
                        let var1 := mulmod(f_33, var0, r)
                        let a_0 := calldataload(0x08e4)
                        let var2 := mulmod(var1, a_0, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_4 := calldataload(0x0964)
                        let var8 := mulmod(var1, a_4, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x1304), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x12e4), sub(r, calldataload(0x12c4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1324), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1324), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x09e4)
                        let f_5 := calldataload(0x0a64)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_5, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_34 := calldataload(0x0e04)
                        let var0 := 0x1
                        let var1 := mulmod(f_34, var0, r)
                        let a_1 := calldataload(0x0904)
                        let var2 := mulmod(var1, a_1, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffe15f
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_5 := calldataload(0x0984)
                        let var8 := mulmod(var1, a_5, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x1364), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x1344), sub(r, calldataload(0x1324)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1384), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1384), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_6 := calldataload(0x0a84)
                        table := f_6
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_35 := calldataload(0x0e24)
                        let a_0 := calldataload(0x08e4)
                        let var0 := mulmod(f_35, a_0, r)
                        let var1 := 0x1
                        let var2 := sub(r, f_35)
                        let var3 := addmod(var1, var2, r)
                        let var4 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff
                        let var5 := mulmod(var3, var4, r)
                        let var6 := addmod(var0, var5, r)
                        input_0 := var6
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x13c4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x13a4), sub(r, calldataload(0x1384)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x13e4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x13e4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_6 := calldataload(0x0a84)
                        table := f_6
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_36 := calldataload(0x0e44)
                        let a_1 := calldataload(0x0904)
                        let var0 := mulmod(f_36, a_1, r)
                        let var1 := 0x1
                        let var2 := sub(r, f_36)
                        let var3 := addmod(var1, var2, r)
                        let var4 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff
                        let var5 := mulmod(var3, var4, r)
                        let var6 := addmod(var0, var5, r)
                        input_0 := var6
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x1424), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x1404), sub(r, calldataload(0x13e4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, r)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, r)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), r)
                    diff := mulmod(diff, mload(0x03e0), r)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), r)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), r)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x03a0), r)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_0, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0380), r)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x03e0), r)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(r, point_3), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x03e0), r)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120, r)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0e64), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r), r)
                    for
                        {
                            let mptr := 0x0f64
                            let mptr_end := 0x0e64
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    for
                        {
                            let mptr := 0x0e44
                            let mptr_end := 0x09a4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1424), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x13c4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1364), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1304), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x12a4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1244), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x11e4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1184), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1124), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x10c4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0984), r), r)
                    for
                        {
                            let mptr := 0x0944
                            let mptr_end := 0x08c4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x09a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0964), r), r)
                    r_eval := mulmod(r_eval, mload(0x0440), r)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1024), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0fe4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1004), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0fc4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0f84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0fa4), r), r)
                    r_eval := mulmod(r_eval, mload(0x0460), r)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x13e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1404), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1384), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x13a4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1324), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1344), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x12c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x12e4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1264), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1284), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1204), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1224), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x11a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x11c4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1144), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1164), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x10e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1104), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1084), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x10a4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1044), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1064), r), r)
                    r_eval := mulmod(r_eval, mload(0x0480), r)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), r)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), r)
                    sum := addmod(sum, mload(0xc0), r)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), r)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80, r)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), r)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), r)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x07a4))
                    mstore(0x20, calldataload(0x07c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x1340
                            let mptr_end := 0x0800
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0424
                            let mptr_end := 0x0164
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0124
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x04a4))
                    mstore(0xa0, calldataload(0x04c4))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0464), calldataload(0x0484))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0764))
                    mstore(0xa0, calldataload(0x0784))
                    for
                        {
                            let mptr := 0x0724
                            let mptr_end := 0x04a4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1444))
                    mstore(0xa0, calldataload(0x1464))
                    success := ec_mul_tmp(success, sub(r, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1484))
                    mstore(0xa0, calldataload(0x14a4))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x1484))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x14a4))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}