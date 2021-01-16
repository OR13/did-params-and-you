module.exports = (uri) => {
  if (uri === "https://www.w3.org/ns/did/v1") {
    return {
      documentUrl: uri,
      document: require("./contexts/did-v1.json"),
    };
  }
  if (uri === "https://www.w3.org/2018/credentials/v1") {
    return {
      documentUrl: uri,
      document: require("./contexts/cred-v1.json"),
    };
  }
  if (
    uri === "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ) {
    return {
      documentUrl: uri,
      document: require("./contexts/lds-jws-v1.json"),
    };
  }

  if (uri === "https://w3id.org/security/v2") {
    return {
      documentUrl: uri,
      document: require("./contexts/sec-v2.json"),
    };
  }

  if (uri === "https://w3id.org/security/v1") {
    return {
      documentUrl: uri,
      document: require("./contexts/sec-v1.json"),
    };
  }

  console.log(uri);
  throw new Error("unsupported context");
};
