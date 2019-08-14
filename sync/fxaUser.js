module.exports = function (xhr, jwcrypto, P, FxAccountsClient) {

  if (!xhr) xhr = require('xmlhttprequest').XMLHttpRequest;
  if (!jwcrypto) {
    jwcrypto = require('browserid-crypto');
    require("browserid-crypto/lib/algs/rs");
    require("browserid-crypto/lib/algs/ds");
  }
  if (!P) P = Promise;
  if (!FxAccountsClient) FxAccountsClient = require('fxa-js-client');

  var certDuration = 3600 * 24 * 365;

  /*
   * 1. use fxa-client to log in to Fxa with email password
   * 2. generate a BrowserID keypair
   * 3. send public key to fxa server and get a cert
   * 4. generate a BrowserID assertion with the new cert
   */

  function FxUser(creds, options) {
    this.email = creds.email;
    this.password = creds.password;
    this.options = options;
    this.client = new FxAccountsClient(
      this.options.fxaServerUrl || 'http://127.0.0.1:9000',
      {xhr: xhr}
    );
  }

  FxUser.prototype.auth = async function (unblockCode) {
    let creds = await this.client.signIn(
      this.email,
      this.password,
      {
        keys: true,
        unblockCode: unblockCode
      }
    );
    this.creds = creds;
    let result = await this.client.accountKeys(creds.keyFetchToken, creds.unwrapBKey);
    this.creds.kB = result.kB;
    this.creds.kA = result.kA;
    return this;
  };

  FxUser.prototype._exists = function (email) {
    var client = new FxAccountsClient(this.options.fxaServerUrl);
    return client.accountExists(email);
  };

  FxUser.prototype.setup = async function (unblockCode) {
    let self = this;
    if (!unblockCode) {
      await this.client.sendUnblockCode(this.email);
      throw new Error("Unblock code unspecified. Sent request. Check your E-Mail.");
    }

    // initialize the client and obtain keys
    await this.auth(unblockCode);
    let status = await this.client.recoveryEmailStatus(self.creds.sessionToken);
    if (!status.verified) {
      // poll for verification or throw?
      throw new Error("Unverified account");
    }
    let creds = self.creds;

    // set the sync key
    self.syncKey = Buffer.from(creds.kB, 'hex');

    return new Promise((resolve, reject) => {
      // upon allocation of a user, we'll gen a keypair and get a signed cert
      jwcrypto.generateKeypair({algorithm: "DS", keysize: 256}, (err, kp) => {
        if (err) return reject(err);
        var duration = self.options.certDuration || certDuration;
        self._keyPair = kp;
        var expiration = +new Date() + duration;

        return self.client.certificateSign(
          self.creds.sessionToken,
          kp.publicKey.toSimpleObject(),
          duration
        ).then(cert => {
          self._cert = cert.cert;
          resolve(self);
        });
      });
    });
  };

  FxUser.prototype.getCert = function (keyPair) {
    var duration = typeof this.options.certDuration !== 'undefined' ?
      this.options.certDuration :
      60 * 60 * 1000;
    return this.client.certificateSign(
      this.creds.sessionToken,
      keyPair.publicKey.toSimpleObject(),
      duration
    ).then(cert => {
      self._cert = cert.cert;
      return self;
    });
  };

  FxUser.prototype.getAssertion = function (audience, duration) {
    var self = this;
    var expirationDate = +new Date() + (typeof duration !== 'undefined' ? duration : 60 * 60 * 1000);

    return new Promise((resolve, reject) => {
      jwcrypto.assertion.sign({},
        {
          audience: audience,
          issuer: this.options.fxaServerUrl,
          expiresAt: expirationDate
        },
        this._keyPair.secretKey,
        function (err, signedObject) {
          if (err) return reject(err);

          var backedAssertion = jwcrypto.cert.bundle([self._cert], signedObject);
          resolve(backedAssertion);
        });
    });
  };

  return FxUser;
};
