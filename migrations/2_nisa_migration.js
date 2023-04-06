const alt_bn128 = artifacts.require("alt_bn128");
const nisa = artifacts.require("NISA");

module.exports = async function(deployer){
  // deployment steps
  await deployer.deploy(alt_bn128);
  await deployer.link(alt_bn128, nisa);
  await deployer.deploy(nisa);

  const inst = await nisa.deployed();
  const a = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
  const param = await inst.generateParam(a);
  const p = await inst.prove.call(param, a);
  var gas = await inst.prove.estimateGas(param, a);
  console.log("proof", gas);
  const result = await inst.verify(param, p);
  gas = await inst.verify.estimateGas(param, p);
  console.log("verify", result, gas);
};