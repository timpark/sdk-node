var Q, request,
  indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

request = require('request');

Q = require('q');

module.exports = function(csrf_generator, cache, requestio) {
  var a;
  a = {
    refresh_tokens: function(credentials, session, force) {
      var defer, now;
      defer = Q.defer();
      credentials.refreshed = false;
      now = new Date();
      if (credentials.refresh_token && ((credentials.expires && now.getTime() > credentials.expires) || force)) {
        request.post({
          url: cache.oauthd_url + cache.oauthd_base + '/refresh_token/' + credentials.provider,
          form: {
            token: credentials.refresh_token,
            key: cache.public_key,
            secret: cache.secret_key
          }
        }, function(e, r, body) {
          var error, k;
          if (e) {
            defer.reject(e);
            return defer.promise;
          } else {
            if (typeof body === "string") {
              try {
                body = JSON.parse(body);
              } catch (error) {
                e = error;
                defer.reject(e);
              }
              if (typeof body === "object" && body.access_token && body.expires_in) {
                credentials.expires = new Date().getTime() + body.expires_in * 1000;
                for (k in body) {
                  credentials[k] = body[k];
                }
                if ((session != null)) {
                  session.oauth = session.oauth || {};
                  session.oauth[credentials.provider] = credentials;
                }
                credentials.refreshed = true;
                credentials.last_refresh = new Date().getTime();
                return defer.resolve(credentials);
              } else {
                return defer.resolve(credentials);
              }
            }
          }
        });
      } else {
        defer.resolve(credentials);
      }
      return defer.promise;
    },
    redirect: function(provider, urlToRedirect, req, res, next) {
      var csrf_token;
      if (cache.logging) {
        cache.log("[oauthio] Redirect to " + cache.oauthd_url + cache.oauthd_base + '/' + provider + " with k=" + cache.public_key + " and redirect_uri=" + urlToRedirect + " from " + (req.get && req.get('Host')));
      }
      csrf_token = csrf_generator(req.session);
      res.writeHead(302, {
        Location: cache.oauthd_url + cache.oauthd_base + '/' + provider + '?k=' + cache.public_key + '&opts=' + encodeURIComponent(JSON.stringify({
          state: csrf_token
        })) + '&redirect_type=server&redirect_uri=' + encodeURIComponent(urlToRedirect)
      });
      res.end();
      return next();
    },
    auth: function(provider, session, opts) {
      var defer;
      defer = Q.defer();
      if (typeof session === "function") {
        return a.redirect(provider, session);
      }
      if (opts != null ? opts.code : void 0) {
        return a.authenticate(opts.code, session);
      }
      if (opts != null ? opts.credentials : void 0) {
        a.refresh_tokens(opts.credentials, session, opts != null ? opts.force_refresh : void 0).then(function(credentials) {
          return defer.resolve(a.construct_request_object(credentials));
        });
        return defer.promise;
      }
      if ((!(opts != null ? opts.credentials : void 0)) && (!(opts != null ? opts.code : void 0))) {
        if (session.oauth[provider]) {
          a.refresh_tokens(session.oauth[provider], session, opts != null ? opts.force_refresh : void 0).then(function(credentials) {
            return defer.resolve(a.construct_request_object(credentials));
          });
        } else {
          defer.reject(new Error('Cannot authenticate from session for provider \'' + provider + '\''));
        }
        return defer.promise;
      }
      defer.reject(new Error('Could not authenticate, parameters are missing or wrong'));
      return defer.promise;
    },
    construct_request_object: function(credentials) {
      var k, request_object;
      request_object = {};
      for (k in credentials) {
        request_object[k] = credentials[k];
      }
      request_object.get = function(url, options) {
        return requestio.make_request(request_object, 'GET', url, options);
      };
      request_object.post = function(url, options) {
        return requestio.make_request(request_object, 'POST', url, options);
      };
      request_object.patch = function(url, options) {
        return requestio.make_request(request_object, 'PATCH', url, options);
      };
      request_object.put = function(url, options) {
        return requestio.make_request(request_object, 'PUT', url, options);
      };
      request_object.del = function(url, options) {
        return requestio.make_request(request_object, 'DELETE', url, options);
      };
      request_object.me = function(options) {
        return requestio.make_me_request(request_object, options);
      };
      request_object.getCredentials = function() {
        return credentials;
      };
      request_object.wasRefreshed = function() {
        return credentials.refreshed;
      };
      return request_object;
    },
    authenticate: function(code, session) {
      var defer;
      defer = Q.defer();
      request.post({
        url: cache.oauthd_url + cache.oauthd_base + '/access_token',
        form: {
          code: code,
          key: cache.public_key,
          secret: cache.secret_key
        }
      }, function(e, r, body) {
        var doNext;
        doNext = function() {
          var error, ref, response;
          if (e) {
            defer.reject(e);
            return;
          }
          try {
            response = JSON.parse(body);
          } catch (error) {
            e = error;
            defer.reject(new Error('OAuth.io response could not be parsed'));
            return;
          }
          if (cache.logging) {
            if (response.access_token) {
              cache.hideInLog(response.access_token);
            }
            if (response.id_token) {
              cache.hideInLog(response.id_token);
            }
            if (response.oauth_token) {
              cache.hideInLog(response.oauth_token);
            }
            if (response.oauth_token_secret) {
              cache.hideInLog(response.oauth_token_secret);
            }
            if (response.code) {
              cache.hideInLog(response.code);
            }
            if (response.state) {
              cache.hideInLog(response.state);
            }
            cache.log("[oauthio] From POST " + cache.oauthd_url + cache.oauthd_base + '/access_token (' + r.statusCode + '): ', body);
          }
          if ((response.status != null) && response.status === 'error' && (response.message != null)) {
            defer.reject(new Error('OAuth.io / oauthd responded with : ' + response.message));
          }
          if (response.state == null) {
            defer.reject(new Error('State is missing from response'));
            return;
          }
          if (((session != null ? session.csrf_tokens : void 0) == null) || (ref = response.state, indexOf.call(session.csrf_tokens, ref) < 0)) {
            if (cache.logging) {
              cache.log('[oauthio] State is not matching: "' + response.state + '" not in session (' + (session != null ? session.oauthio_logging : void 0) + '):', session != null ? session.csrf_tokens : void 0);
            }
            defer.reject(new Error('State is not matching'));
          }
          if (response.expires_in) {
            response.expires = new Date().getTime() + response.expires_in * 1000;
          }
          response = a.construct_request_object(response);
          if ((session != null)) {
            session.oauth = session.oauth || {};
            session.oauth[response.provider] = response;
          }
          defer.resolve(response);
        };
        if ((typeof session.reload) === 'function') {
          return session.reload(doNext);
        } else {
          cache.log('[oauthio] [warn] req.session should have a "reload" method');
          return doNext();
        }
      });
      return defer.promise;
    }
  };
  return a;
};
