module.exports = function(guid, cache) {
  var logging_sessionCount;
  logging_sessionCount = 0;
  return function(session) {
    var csrf_token;
    csrf_token = guid();
    session.csrf_tokens = session.csrf_tokens || [];
    session.csrf_tokens.push(csrf_token);
    if (session.csrf_tokens.length > 4) {
      session.csrf_tokens.shift();
    }
    if (cache.logging) {
      if (!session.oauthio_logging) {
        session.oauthio_logging = ++logging_sessionCount;
      }
      cache.hideInLog(csrf_token);
      cache.log('[oauthio] Add csrf token "' + csrf_token + '" to session (' + session.oauthio_logging + ')');
    }
    return csrf_token;
  };
};
