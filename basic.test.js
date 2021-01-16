const {
  Ed25519KeyPair,
  Ed25519Signature2018,
} = require("@transmute/ed25519-signature-2018");

const vcjs = require("@transmute/vc.js").ld;
const documentLoader = require("./documentLoader");
it("works", async () => {
  const vc = await vcjs.issue({
    credential: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: "http://example.gov/credentials/3732",
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      issuer: {
        id: "did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg",
      },
      issuanceDate: "2020-03-10T04:24:12.164Z",
      credentialSubject: {
        id: "did:example:456",
      },
    },
    suite: new Ed25519Signature2018({
      key: await Ed25519KeyPair.from({
        id:
          "did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg#z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg",
        type: "Ed25519VerificationKey2018",
        controller: "did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg",
        publicKeyBase58: "g9X6bPg6ZKWvc24zgqMhrXerMXoY878KqPxfBiEVLsJ",
        privateKeyBase58:
          "3tJ2TAfhFgq9hpRwhL3xuM56rNsDzrdDUcYCFcgQ6RbxYRdMQQkrD3yHdMo1E2opqHZcrDWgw23zc5SfMFcP86Hv",
      }),
    }),
    documentLoader,
  });
  const verification = await vcjs.verifyCredential({
    credential: vc,
    suite: new Ed25519Signature2018(),
    documentLoader: (uri) => {
      if (
        uri.includes("did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg")
      ) {
        return {
          documentUrl: uri,
          document: {
            "@context": ["https://www.w3.org/ns/did/v1"],
            id: "did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg",
            assertionMethod: [
              {
                id:
                  "did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg#z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg",
                type: "Ed25519VerificationKey2018",
                controller:
                  "did:key:z6Mkf8QZgqe7S6oz36rmgFoCYx5efvoex1MV1rJtVTgFQZeg",
                publicKeyBase58: "g9X6bPg6ZKWvc24zgqMhrXerMXoY878KqPxfBiEVLsJ",
              },
            ],
          },
        };
      }
      return documentLoader(uri);
    },
  });

  expect(verification.verified).toBe(true);
});
