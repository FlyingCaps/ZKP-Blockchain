const alt_bn128 = artifacts.require("alt_bn128");
const BulletProof = artifacts.require("BulletProof");

module.exports = function(deployer) {
  // deployment steps
  deployer.deploy(alt_bn128);
  deployer.link(alt_bn128, BulletProof);
  deployer.deploy(BulletProof);
};