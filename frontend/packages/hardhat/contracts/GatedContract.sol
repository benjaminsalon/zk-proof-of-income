// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import './Verifier.sol';

contract GatedContract {

    address public verifier_address;
    Halo2Verifier verifier;
    bool public isVerified = false;

    constructor(address _verifier_address) {
        verifier_address =_verifier_address;
        verifier = Halo2Verifier(_verifier_address);
    }

    function verify_contract(
        bytes calldata proof,
        uint256[] calldata instances
        ) public {
        bool res = verifier.verifyProof(proof, instances);
        if (res) {
            isVerified = true;
        }
    }

}