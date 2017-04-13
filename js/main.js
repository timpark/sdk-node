var _authentication, _csrf_generator, _endpoints_initializer, _guid, _requestio, cache, package_info;

_guid = require('./tools/guid');

_csrf_generator = require('./lib/csrf_generator');

_endpoints_initializer = require('./lib/endpoints');

_authentication = require('./lib/authentication');

_requestio = require('./lib/request');

package_info = require('../package.json');

cache = {
  public_key: void 0,
  secret_key: void 0,
  csrf_tokens: [],
  oauthd_url: 'https://oauth.io',
  oauthd_base: '/auth'
};

module.exports = function() {
  var authentication, csrf_generator, endpoints_initializer, guid, oauth, requestio;
  guid = _guid();
  csrf_generator = _csrf_generator(guid, cache);
  requestio = _requestio(cache);
  authentication = _authentication(csrf_generator, cache, requestio);
  endpoints_initializer = _endpoints_initializer(csrf_generator, cache, authentication);
  cache.__hiddenLog = {};
  cache.__hiddenLogCount = 0;
  cache.hideInLog = function(hidden) {
    if (hidden && !(cache.logging && cache.logging.showAll)) {
      hidden = JSON.stringify(hidden);
      if (!cache.__hiddenLog[hidden]) {
        return cache.__hiddenLog[hidden] = ++cache.__hiddenLogCount;
      }
    }
  };
  cache.log = function() {
    var arg, args, i, k, len, ref, ref1, v;
    if ((ref = cache.logging) != null ? ref.silent : void 0) {
      return;
    }
    args = [];
    for (i = 0, len = arguments.length; i < len; i++) {
      arg = arguments[i];
      if ((typeof arg) === 'object') {
        arg = JSON.stringify(arg);
      }
      arg = arg.toString();
      ref1 = cache.__hiddenLog;
      for (k in ref1) {
        v = ref1[k];
        arg = arg.replace(k, "[hidden-" + v + "]");
      }
      args.push(arg);
    }
    return console.log.apply(console, args);
  };
  oauth = {
    initialize: function(app_public_key, app_secret_key) {
      cache.public_key = app_public_key;
      return cache.secret_key = app_secret_key;
    },
    __getCache: function() {
      return cache;
    },
    __clearCache: function() {
      return cache = {
        public_key: void 0,
        secret_key: void 0,
        csrf_tokens: [],
        oauthd_url: 'https://oauth.io',
        oauthd_base: '/auth'
      };
    },
    getAppKey: function() {
      return cache.public_key;
    },
    getAppSecret: function() {
      return cache.secret_key;
    },
    getCsrfTokens: function(session) {
      return session.csrf_tokens;
    },
    setOAuthdUrl: function(url, base) {
      cache.oauthd_url = url;
      if (base) {
        return cache.oauthd_base = base;
      }
    },
    setOAuthdURL: function(url, base) {
      return oauth.setOAuthdUrl(url, base);
    },
    getOAuthdUrl: function() {
      return cache.oauthd_url;
    },
    getOAuthdURL: function() {
      return oauth.getOAuthdUrl();
    },
    getVersion: function() {
      return package_info.version;
    },
    enableLogging: function(options) {
      cache.logging = options;
      if ((typeof cache.logging === "object") && cache.logging.showAll) {
        cache.log('[oauthio] Logging is enabled, these logs contains sensitive informations. Please, be careful before sharing them.');
      } else {
        cache.log('[oauthio] Logging is enabled.');
      }
      return cache.log('[oauthio] node ' + process.version + ', oauthio v' + package_info.version);
    },
    generateStateToken: function(session) {
      return csrf_generator(session);
    },
    initEndpoints: function(app) {
      return endpoints_initializer(app);
    },
    auth: function(provider, session, opts) {
      if (typeof opts === 'undefined' && typeof session === 'string') {
        return oauth.authRedirect(provider, session);
      } else {
        return authentication.auth(provider, session, opts);
      }
    },
    redirect: function(cb) {
      return function(req, res, next) {
        var error, error1, oauthio_data, ref;
        if (typeof req.query !== 'object') {
          return cb(new Error("req.query must be an object (did you used a query parser?)"), req, res);
        }
        if (typeof req.query.oauthio === 'undefined') {
          return cb(new Error("Could not find oauthio in query string"), req, res);
        }
        try {
          oauthio_data = JSON.parse(req.query.oauthio);
          if (cache.logging) {
            if (oauthio_data.data) {
              if (oauthio_data.data.id_token) {
                cache.hideInLog(oauthio_data.data.id_token);
              }
              if (oauthio_data.data.access_token) {
                cache.hideInLog(oauthio_data.data.access_token);
              }
              if (oauthio_data.data.oauth_token) {
                cache.hideInLog(oauthio_data.data.oauth_token);
              }
              if (oauthio_data.data.oauth_token_secret) {
                cache.hideInLog(oauthio_data.data.oauth_token_secret);
              }
              if (oauthio_data.data.code) {
                cache.hideInLog(oauthio_data.data.code);
              }
              if (oauthio_data.data.state) {
                cache.hideInLog(oauthio_data.data.state);
              }
            }
            cache.log('[oauthio] Redirect received from ' + (req.get && req.get('Host')), oauthio_data);
          }
        } catch (error1) {
          error = error1;
          return cb(new Error("Could not parse oauthio results"), req, res);
        }
        if (oauthio_data.status === "error") {
          return cb(new Error(oauthio_data.message || "Authorization error"), req, res);
        }
        if (!((ref = oauthio_data.data) != null ? ref.code : void 0)) {
          return cb(new Error("Could not find code from oauthio results"), req, res);
        }
        return authentication.authenticate(oauthio_data.data.code, req.session).then(function(r) {
          return cb(r, req, res, next);
        }).fail(function(e) {
          return cb(e, req, res, next);
        });
      };
    },
    authRedirect: function(provider, urlToRedirect) {
      return function(req, res, next) {
        if (typeof req.session !== 'object' && typeof next === 'function') {
          return next(new Error("req.session must be an object (did you used a session middleware?)"));
        }
        authentication.redirect(provider, urlToRedirect, req, res, next);
      };
    },
    refreshCredentials: function(credentials, session) {
      return authentication.refresh_tokens(credentials, session, true);
    }
  };
  return oauth;
};
