const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')

const assertions = require('../assertions')
const { generateAuthCode, lookUpByAuthCode } = require('../auth-code')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)

const VERSION_PREFIX = '/v2'
const OAUTH_PREFIX = '/oauth'
const PATH_PREFIX = VERSION_PREFIX + OAUTH_PREFIX

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../../static/certs/spcp-key.pem'),
)

const idGenerator = {
  singPass: ({ nric }) =>
    assertions.myinfo.v3.personas[nric] ? `${nric} [MyInfo]` : nric,
}

const buildAssertURL = (redirectURI, authCode, state) =>
  `${redirectURI}?code=${encodeURIComponent(
    authCode,
  )}&state=${encodeURIComponent(state)}`

function config(app, { showLoginPage, isStateless }) {
  const profiles = assertions.oidc.singPass
  const defaultProfile =
    profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

  app.get(`${PATH_PREFIX}/authorize`, (req, res) => {
    const { redirect_uri: redirectURI, state, nonce } = req.query
    const scopes = req.query.scope ?? 'openid'
    console.info(`Requested scope ${scopes}`)
    if (showLoginPage(req)) {
      const values = profiles
        .filter((profile) => assertions.myinfo.v3.personas[profile.nric])
        .map((profile) => {
          const authCode = generateAuthCode(
            { profile, scopes, nonce },
            { isStateless },
          )
          const assertURL = buildAssertURL(redirectURI, authCode, state)
          const id = idGenerator.singPass(profile)
          return { id, assertURL }
        })
      const response = render(LOGIN_TEMPLATE, { values })
      res.send(response)
    } else {
      const profile = defaultProfile
      const authCode = generateAuthCode(
        { profile, scopes, nonce },
        { isStateless },
      )
      const assertURL = buildAssertURL(redirectURI, authCode, state)
      console.info(
        `Redirecting login from ${req.query.client_id} to ${assertURL}`,
      )
      res.redirect(assertURL)
    }
  })

  app.post(
    `${PATH_PREFIX}/token`,
    express.json(),
    express.urlencoded({ extended: true }),
    async (req, res) => {
      console.log(req.body)
      const { client_id: aud, code: authCode } = req.body

      console.info(
        `Received auth code ${authCode} from ${aud} and ${req.body.redirect_uri}`,
      )

      try {
        const { profile, scopes, nonce } = lookUpByAuthCode(authCode, {
          isStateless,
        })
        console.info(
          `Profile ${JSON.stringify(profile)} with token scope ${scopes}`,
        )
        const accessToken = authCode
        const iss = `${req.protocol}://${req.get('host') + VERSION_PREFIX}`

        const { idTokenClaims, refreshToken } = assertions.oidc.create.singPass(
          profile,
          iss,
          aud,
          nonce,
          accessToken,
        )
        // Change sub from `s=${nric},u=${uuid}`
        // to `u=${uuid}` to be consistent with userinfo sub
        idTokenClaims.sub = idTokenClaims.sub.split(',')[1]

        const signingKey = await jose.JWK.asKey(signingPem, 'pem')
        const idToken = await jose.JWS.createSign(
          { format: 'compact' },
          signingKey,
        )
          .update(JSON.stringify(idTokenClaims))
          .final()

        res.json({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 24 * 60 * 60,
          scope: scopes,
          token_type: 'Bearer',
          id_token: idToken,
        })
      } catch (error) {
        console.error(error)
        res.status(500).json({ message: error.message })
      }
    },
  )

  app.get(`${PATH_PREFIX}/userinfo`, async (req, res) => {
    const authCode = (
      req.headers.authorization || req.headers.Authorization
    ).replace('Bearer ', '')
    // eslint-disable-next-line no-unused-vars
    const { profile, scopes, unused } = lookUpByAuthCode(authCode, {
      isStateless,
    })

    console.info(`userinfo scopes ${scopes}`)

    const claims = profile.claims || {}
    res.json({
      sub: profile.uuid || profile.nric,
      name: getClaimValue(claims.name),
      email: getClaimValue(claims.email),
      phone_number: formatPhoneNumber(claims.mobileno),
    })
  })

  app.get(`${VERSION_PREFIX}/.well-known/jwks.json`, async (_req, res) => {
    const key = await jose.JWK.asKey(signingPem, 'pem')
    const jwk = key.toJSON()
    jwk.use = 'sig'
    res.json({ keys: [jwk] })
  })

  app.get(
    `${VERSION_PREFIX}/.well-known/openid-configuration`,
    async (req, res) => {
      const issuer = `${req.protocol}://${req.get('host') + VERSION_PREFIX}`

      res.json({
        issuer,
        authorization_endpoint: `${issuer}${OAUTH_PREFIX}/authorize`,
        token_endpoint: `${issuer}${OAUTH_PREFIX}/token`,
        userinfo_endpoint: `${issuer}${OAUTH_PREFIX}/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        claims_supported: [
          'nonce',
          'aud',
          'iss',
          'sub',
          'exp',
          'iat',
          'name',
          'email',
          'phone_number',
        ],
        // Note: some of these scopes are not yet officially documented
        // in https://docs.id.gov.sg/data-catalog
        // So they are not officially supported yet.
        scopes_supported: [
          'openid',
          'myinfo.nric_number',
          'myinfo.name',
          'myinfo.email',
          'myinfo.sex',
          'myinfo.race',
          'myinfo.mobile_number',
          'myinfo.registered_address',
          'myinfo.date_of_birth',
          'myinfo.passport_number',
          'myinfo.passport_expiry_date',
          'myinfo.nationality',
          'myinfo.residentialstatus',
          'myinfo.residential',
          'myinfo.housingtype',
          'myinfo.hdbtype',
          'myinfo.birth_country',
          'myinfo.vehicles',
          'myinfo.name_of_employer',
          'myinfo.workpass_status',
          'myinfo.workpass_expiry_date',
          'myinfo.marital_status',
          'myinfo.mobile_number_with_country_code',
        ],
        id_token_signing_alg_values_supported: ['RS256'],
        subject_types_supported: ['pairwise'],
      })
    },
  )
}

const getClaimValue = (claim) => claim?.value

const formatPhoneNumber = (phone) =>
  [phone?.prefix?.value, phone?.areacode?.value, phone?.nbr?.value].join('')

module.exports = config
