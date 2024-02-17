// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
const hre = require("hardhat");

async function main() {

  const verifier = await hre.ethers.deployContract("Halo2Verifier");

  await verifier.waitForDeployment();
  const deploy_address_json = {
    verifier_address: verifier.target
  }
  var fs = require('fs');
  fs.writeFile("deploy_addresses.json", JSON.stringify(deploy_address_json), function(err: any) {
      if (err) {
          console.log(err);
      }
  });


  console.log(
    `Verifier contract deployed to ${verifier.target}`
  );
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
