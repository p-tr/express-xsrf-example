const express = require('express');
const jwt = require('jsonwebtoken');
const bp = require('body-parser');
const cp = require('cookie-parser');
const { nanoid } = require('nanoid');

const port = 4000;
const host = '127.0.0.1';

const algorithm = 'HS512';

const secret = nanoid(128);

const app = express();

app.use(cp());
app.use(bp.json());

app.use((req, res, next) => {
  req.context = {};

  next();
})

// Middleware n°1
//  Vérifie la validité du JWT s'il existe :-)
app.use((req, res, next) => {
  if('Authorization' in req.cookies) {
    const token = req.cookies['Authorization'];

    try {
      req.context = jwt.verify(token, secret);
      console.log(req.context);
    } catch(err) {
      next(err);
    }
  }

  next();
});

// Middleware n°2
//  Valide et Met à jour le jeton XSRF pour le contexte d'authentification courant
app.use((req, res, next) => {
  const xsrf_token = nanoid(128);

  if('xsrf_token' in req.context) {
    // 1. cookie annexe qui contient le token XSRF
    // 2. header x-xsrf-token
    // 3. le token est aussi dans le JWT
    //  Valide si : 1 == 2 == 3
    const xsrf_cookie = req.cookies['XSRF-TOKEN'];
    const xsrf_header = req.get('x-xsrf-token');
    const { xsrf_token } = req.context;

    if(!(xsrf_cookie === xsrf_header && xsrf_header === xsrf_token && xsrf_token === xsrf_cookie)) {
      next({
        name: 'XsrfValidationError',
        message: 'Invalid XSRF token'
      });
    }
  }

  req.context.xsrf_token = xsrf_token;

  next();
});

app.route('/')
  .get((req, res, next) => {
    const { sub, xsrf_token } = req.context;
    const payload = { sub, xsrf_token };
    const options = { algorithm };

    const token = jwt.sign(payload, secret, options);

    res.cookie('Authorization', token, { httpOnly: true });
    res.cookie('XSRF-TOKEN', xsrf_token);

    res.json({ token });
  });

app.use((err, req, res, next) => {
  res.status(500).json({ err });
});

app.listen({ host, port }, () => {
  console.log(`server is listening on ${host}:${port} ...`);
});
