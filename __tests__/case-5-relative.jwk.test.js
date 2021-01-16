const {
  JsonWebKey,
  JsonWebSignature,
} = require("@transmute/json-web-signature-2020");

const vcjs = require("@transmute/vc.js").ld;
const documentLoader = require("../documentLoader");

let fixture = {};

it("case-5-relative.jwk", async () => {
  const vc = await vcjs.issue({
    credential: {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        // required because credentials/v1 does not understand JsonWebSignature2020
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
      ],
      id: "http://example.gov/credentials/3732",
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      issuer: {
        id: "did:example:123",
      },
      issuanceDate: "2020-03-10T04:24:12.164Z",
      credentialSubject: {
        id: "did:example:456",
      },
    },
    suite: new JsonWebSignature({
      key: await JsonWebKey.from({
        id: "did:example:123#credential-issuance-key",
        type: "JsonWebKey2020",
        controller: "did:example:123",
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
    documentLoader: (uri) => {
      return documentLoader(uri);
    },
  });

  fixture = { ...fixture, [vc.id]: vc };
  const verification = await vcjs.verifyCredential({
    credential: vc,
    suite: new JsonWebSignature(),
    documentLoader: (uri) => {
      if (uri.includes("did:example:123")) {
        const didDocument = {
          // Note no extension required, because did/v1 understands JsonWebKey2020
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: "did:example:123",
          publicKey: [
            {
              id: "#credential-issuance-key",
              type: "JsonWebKey2020",
              controller: "did:example:123",
              publicKeyJwk: {
                kty: "OKP",
                crv: "Ed25519",
                x: "fnwl8GAH_K2uHFjQLxQmKq826Mg-DznY4Wmex-LFhYA",
              },
            },
          ],
          assertionMethod: ["#credential-issuance-key"],
          authentication: ["#credential-issuance-key"],
        };

        fixture = { ...fixture, [didDocument.id]: didDocument };
        return {
          documentUrl: uri,
          document: didDocument,
        };
      }
      return documentLoader(uri);
    },
  });

  expect(verification.verified).toBe(true);
  require("fs").writeFileSync(
    require("path").resolve(__dirname, "../examples/case-5-legal-working.json"),
    JSON.stringify(fixture, null, 2)
  );
});
