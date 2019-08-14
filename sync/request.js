module.exports = function (XHR, hawkClient, P) {
  if (!P) P = Promise;
  if (!XHR) XHR = require("xmlhttprequest").XMLHttpRequest;
  if (!hawkClient) hawkClient = require("hawk").client;

  function Request(baseUrl, options) {
    this.baseUrl = baseUrl;
    this.credentials = options && options.credentials;
  }

  Request.prototype.get = function (path, options) {
    if (!options) options = {};
    options.method = 'GET';
    return this.request(path, options);
  };

  Request.prototype.post = function (path, payload, options) {
    if (!options) options = {};
    options.method = 'POST';
    options.json = payload;
    return this.request(path, options);
  };

  Request.prototype.put = function (path, payload, options) {
    if (!options) options = {};
    options.method = 'PUT';
    options.json = payload;
    return this.request(path, options);
  };

  Request.prototype.request = function request(path, options) {
    return new Promise((resolve, reject) => {
      var xhr = new XHR();
      var uri = this.baseUrl + path;
      var credentials = options.credentials || this.credentials;
      var payload;

      if (options.json) {
        payload = JSON.stringify(options.json);
      }

      xhr.open(options.method, uri);
      xhr.onerror = function onerror() {
        reject(xhr.responseText);
      };
      xhr.onload = function onload() {
        let result;
        if (xhr.responseText === 'Unauthorized') return reject(xhr.responseText);
        try {
          result = JSON.parse(xhr.responseText);
        } catch (e) {
          return reject(xhr.responseText);
        }
        if (result.error || xhr.status >= 400) {
          return reject(result);
        }
        resolve(result);
      };

      // calculate Hawk header if credentials are supplied
      if (credentials) {
        let authHeader = hawkClient.header(uri, options.method, {
          credentials: credentials,
          payload: payload,
          contentType: "application/json"
        });
        xhr.setRequestHeader("authorization", authHeader.header);
      }

      for (let header in options.headers) {
        xhr.setRequestHeader(header, options.headers[header]);
      }

      xhr.setRequestHeader("Content-Type", "application/json");

      xhr.send(payload);
    });
  };

  return Request;
};
