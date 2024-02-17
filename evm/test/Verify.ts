import {
    time,
    loadFixture,
  } from "@nomicfoundation/hardhat-toolbox/network-helpers";
  import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
  import { expect } from "chai";
  import { ethers } from "hardhat";
  
  import proof_data from '../../ezkl/proof_data.json';

  describe("Verify", function () {
  
    describe("Verify test proof", function () {
      it("Should return true for a correct proof", async function () {
        let verify_contract = await ethers.deployContract("Halo2Verifier");
        let proof = proof_data.hex_proof;
        let instances = proof_data.instances;
        let instances_number = [Number(0),Number(0),Number(0)];
        for (let i = 0; i < instances.length; i++) {
            instances_number[i] = Number(instances[i])
        }
        let res = await verify_contract.verifyProof(proof,instances_number);
        console.log("res is ", res)
      });
    });
  });
  