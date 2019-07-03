(async () => {
  const epoch = () => Date.now() / 1000 | 0;

  const alg = {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: { name: 'SHA-256' },
  };

  let privateKey;
  let publicKey;

  const toJWK = async () => {
    const { ext, key_ops, ...jwk } = await window.crypto.subtle.exportKey('jwk', publicKey);

    return jwk;
  }

  // keypair generation / retrieval
  const db = new Dexie('datastore');
  db.version(1).stores({ keys: '', response: '' });
  try {
    ({ privateKey, publicKey } = await db.keys.get(1) || {});

    if (!privateKey || !publicKey) {
      ({ privateKey, publicKey } = await window.crypto.subtle.generateKey(alg, false, ['sign']))

      await db.keys.put({ privateKey, publicKey }, 1);
    }
  } catch (err) {
    console.error('failed to retrieve / generate keys');
    throw err;
  }

  const base64url = {
    encode: function (a) {
      var base64string = btoa(String.fromCharCode.apply(0, a));
      return base64string.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    },
    decode: function (s) {
      s = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
      return new Uint8Array(Array.prototype.map.call(atob(s), function (c) { return c.charCodeAt(0); }));
    }
  }

  // JWT creation and signing
  const charset = 'Uint8ArdomValuesObj012345679BCDEFGHIJKLMNPQRSTWXYZ_cfghkpqvwxyz-';
  const nanoid = () => {
    let size = 21;
    var id = '';
    var bytes = crypto.getRandomValues(new Uint8Array(size));
    while (0 < size--) {
      id += charset[bytes[size] & 63];
    }
    return id;
  }

  const utf8ToUint8Array = (str) => {
    const chars = [];
    str = window.btoa(unescape(encodeURIComponent(str)));
    return base64url.decode(str);
  }

  const jwt = async (header, payload) => {
    payload.iat = epoch()
    payload.jti = nanoid()

    const payloadAsJSON = JSON.stringify(payload);
    const headerAsJSON = JSON.stringify(header);

    const partialToken = [
      base64url.encode(utf8ToUint8Array(headerAsJSON)), base64url.encode(utf8ToUint8Array(payloadAsJSON))
    ].join('.');

    const characters = payloadAsJSON.split('');
    const it = utf8ToUint8Array(payloadAsJSON).entries();
    let i = 0;
    const result = [];

    while (!(current = it.next()).done) {
      result.push([current.value[1], characters[i]]);
      i++;
    }

    const messageAsUint8Array = utf8ToUint8Array(partialToken);

    const signature = await crypto.subtle.sign(alg, privateKey, messageAsUint8Array)
    const signatureAsBase64 = base64url.encode(new Uint8Array(signature));
    return `${partialToken}.${signatureAsBase64}`;
  };

  const dpopToken = async (uri, method = 'POST') => jwt({ typ: 'dpop+jwt', alg: 'ES256', jwk: await toJWK(publicKey) }, { http_uri: uri, http_method: method });

  // AS Discovery
  let introspection_endpoint, token_endpoint, userinfo_endpoint
  await (async () => {
    const response = await fetch('https://op.panva.cz/.well-known/openid-configuration');
    ({ introspection_endpoint, token_endpoint, userinfo_endpoint } = await response.json());
  })();

  // callback
  const query = (variable) => {
    const query = window.location.search.substring(1);
    const vars = query.split('&');
    for (var i = 0; i < vars.length; i++) {
      const pair = vars[i].split('=');
      if (decodeURIComponent(pair[0]) == variable) {
        return decodeURIComponent(pair[1]);
      }
    }
  }

  if (window.location.pathname === '/cb') {
    const code = query('code');
    const error = query('error');

    if (error) {
      throw new Error('authorization failed');
    } else if (!code) {
      throw new Error('expected authorization code');
    }

    const tokenRequestBody = new URLSearchParams();
    tokenRequestBody.append('grant_type', 'authorization_code');
    tokenRequestBody.append('code', code);
    tokenRequestBody.append('client_id', 'dpop-heroku');

    const tokenResponse = await fetch(token_endpoint, {
      method: 'POST',
      headers: new Headers({
        'content-type': 'application/x-www-form-urlencoded',
        'DPoP': await dpopToken(token_endpoint),
      }),
      body: tokenRequestBody.toString(),
    });

    await db.response.put(await tokenResponse.json(), 1);

    window.location = '/';
  }

  const append = (text) => {
    const [output] = document.getElementsByTagName('output');
    output.innerHTML += `\n${text}`
  }

  const tokens = await db.response.get(1);

  if (!tokens) {
    return;
  }

  append(`stored token response: ${JSON.stringify(tokens, null, 4)}`);

  let introspection;
  for (const type of ['refresh_token', 'access_token']) {
    const introspectionRequestBody = new URLSearchParams();
    introspectionRequestBody.append('token', tokens[type]);
    introspectionRequestBody.append('client_id', 'dpop-heroku');
    introspectionRequestBody.append('token_type_hint', type);

    const introspectionResponse = await fetch(introspection_endpoint, {
      method: 'POST',
      headers: new Headers({
        'content-type': 'application/x-www-form-urlencoded',
      }),
      body: introspectionRequestBody.toString(),
    });

    introspection = await introspectionResponse.json();
    append(`\n${type} introspection response: ${JSON.stringify(introspection, null, 4)}`);
  }


  if (introspection.active) {
    const userinfoResponse = await fetch(userinfo_endpoint, {
      method: 'GET',
      headers: new Headers({
        'DPoP': await dpopToken(userinfo_endpoint, 'GET'),
        'Authorization': `DPoP ${tokens.access_token}`
      })
    });

    const userinfo = await userinfoResponse.json();
    append('\ncan you use the access or refresh tokens? Nope, only those with access to this javascript runtime context can.');

    append(`\nuserinfo response: ${JSON.stringify(userinfo)}`);

    append(`\nAnd the best part, i can't even tell you what the private key is.`);
  }

  window.refresh = async () => {
    const refreshRequestBody = new URLSearchParams();
    refreshRequestBody.append('grant_type', 'refresh_token');
    refreshRequestBody.append('refresh_token', tokens.refresh_token);
    refreshRequestBody.append('client_id', 'dpop-heroku');

    const refreshResponse = await fetch(token_endpoint, {
      method: 'POST',
      headers: new Headers({
        'DPoP': await dpopToken(token_endpoint),
        'content-type': 'application/x-www-form-urlencoded',
      }),
      body: refreshRequestBody.toString(),
    });

    await db.response.put(await refreshResponse.json(), 1);
    window.location = window.location
    return false;
  }

  append(`\n<a href="#" onclick="refresh(); return false;">refresh tokens</a>`);
})();
