const {
  JsonWebKey,
  JsonWebSignature,
} = require("@transmute/json-web-signature-2020");

const vcjs = require("@transmute/vc.js").ld;
const documentLoader = require("./documentLoader");
it.skip("works", async () => {
  const vc = await vcjs.issue({
    credential: {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
      ],
      id: "http://example.gov/credentials/3732",
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      issuer: {
        id: "did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35",
      },
      issuanceDate: "2020-03-10T04:24:12.164Z",
      credentialSubject: {
        id: "did:example:456",
      },
    },
    suite: new JsonWebSignature({
      key: await JsonWebKey.from({
        id:
          "did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35#z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35",
        type: "JsonWebKey2020",
        controller: "did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35",
        publicKeyJwk: {
          crv: "Ed25519",
          x: "fnwl8GAH_K2uHFjQLxQmKq826Mg-DznY4Wmex-LFhYA",
          kty: "OKP",
        },
        privateKeyJwk: {
          crv: "Ed25519",
          d: "gJE_1hJ0MimxW7I0hqZoIuOg37KnQkkJex_zl1VlrIY",
          x: "fnwl8GAH_K2uHFjQLxQmKq826Mg-DznY4Wmex-LFhYA",
          kty: "OKP",
        },
      }),
    }),
    documentLoader,
  });

  const verified = await vcjs.verifyCredential({
    credential: vc,
    suite: new JsonWebSignature(),
    documentLoader: (uri) => {
      if (
        uri.includes("did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35")
      ) {
        return {
          documentUrl: uri,
          document: {
            "@context": [
              "https://www.w3.org/ns/did/v1",
              "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
            ],
            id: "did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35",
            assertionMethod: [
              {
                id:
                  "did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35#z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35",
                type: "JsonWebKey2020",
                controller:
                  "did:key:z6Mkny1DHkp7ySQVeR1omUY8NTWsFf77bSc1TbEV2KTZBX35",
                publicKeyJwk: {
                  crv: "Ed25519",
                  x: "fnwl8GAH_K2uHFjQLxQmKq826Mg-DznY4Wmex-LFhYA",
                  kty: "OKP",
                },
              },
            ],
          },
        };
      }
      return documentLoader(uri);
    },
  });

  console.log("sadf", verified);
});
