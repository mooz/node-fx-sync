let XHR = null;
let hawkClient = require("hawk").client;

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
  if (!XHR) XHR = require("xmlhttprequest").XMLHttpRequest;

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
      reject(xhr);
    };
    xhr.onload = function onload() {
      let result;
      if (xhr.responseText === 'Unauthorized') return reject(xhr);
      try {
        result = JSON.parse(xhr.responseText);
      } catch (e) {
        return reject(xhr);
      }
      if (result.error || xhr.status >= 400) {
        return reject(JSON.stringify({error: result.error, status: xhr.status}));
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

module.exports = Request;
