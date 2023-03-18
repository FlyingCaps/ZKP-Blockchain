const alt_bn128 = artifacts.require("alt_bn128");
const nisa = artifacts.require("NISA");

module.exports = function(deployer){
  // deployment steps
  deployer.deploy(alt_bn128);
  deployer.link(alt_bn128, nisa);
  deployer.deploy(nisa);
};