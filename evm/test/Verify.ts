import {
    time,
    loadFixture,
  } from "@nomicfoundation/hardhat-toolbox/network-helpers";
  import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
  import { expect } from "chai";
  import { ethers } from "hardhat";
  
//   let ethers = require('./node_modules/ethers')

  import proof_data from '../../ezkl/proof_data.json';

  describe("Verify", function () {
  
    describe("Verify test proof", function () {
      it("Should return true for a correct proof", async function () {

        let verify_contract = await ethers.deployContract("Halo2Verifier");

        let gated_contract = await ethers.deployContract("GatedContract",[verify_contract.target])

        let proof = proof_data.hex_proof;
        let instances = proof_data.pretty_public_inputs.outputs;
        let instances_number = []
        for (let i = 0; i < instances[0].length; i++) {
            let number = BigInt(instances[0][i])
            console.log(instances[0][i])
            console.log(number)
            instances_number.push(BigInt(instances[0][i]))
        }

        console.log(instances_number[0])
        
        // verify_contract.abi.encodeWithSignature("verifyProof(bytes,uint256[])", transferContractAdr, transferPayload);

        // We check that the contract is initially not verified:
        let is_verified = await gated_contract.isVerified();
        console.log("Before verification, gated contract isVerified is ", is_verified)
        expect(is_verified).to.be.false;
        let tx = await gated_contract.verify_contract(proof,instances_number);
        let res = await tx.wait();
        
        is_verified = await gated_contract.isVerified();
        console.log("After verification, gated contract isVerified is ", is_verified)
        expect(is_verified).to.be.true;
    });
});
});
