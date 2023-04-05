const alt_bn128 = artifacts.require("alt_bn128");
const nisa2 = artifacts.require("NISA2");

module.exports = function(deployer){
  // deployment steps
  deployer.deploy(alt_bn128);
  deployer.link(alt_bn128, nisa2);
  deployer.deploy(nisa2);
};