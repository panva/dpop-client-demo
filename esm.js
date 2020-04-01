import DPoP, { generateKeyPair } from 'https://cdn.jsdelivr.net/npm/dpop@^0.5.0';

window.DPoP = DPoP;
window.generateKeyPair = generateKeyPair;

for (const alg of ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512']) {
  (async function () {
    const keypair = await generateKeyPair(alg);
    const dpopToken = await DPoP(keypair, alg, 'https://rs.example.com/resource', 'GET');
    console.log(`${alg} works`);
    console.log(dpopToken);
  })().catch(function (err) {
    console.log(`${alg} failed`);
    console.log(err);
  });
}
