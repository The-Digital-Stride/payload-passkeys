# Security policy

`@the-digital-stride/payload-passkeys` controls who can sign in to a Payload admin, so we treat every report as urgent.

## Supported versions

| Version                               | Supported                       |
| ------------------------------------- | ------------------------------- |
| The latest minor of the current major | Yes                             |
| Anything older                        | No: upgrade to the latest minor |

Before 1.0.0, only the latest `0.x` release is supported.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. The report stays private between you and the maintainers.

Please don't open a public issue, discussion or pull request about a vulnerability, and don't send exploit details by email.

A useful report says which version and Payload version you tested, the database adapter, the steps or a proof of concept, and what an attacker gains.

## What to expect

- We acknowledge your report within 3 working days, and send a first assessment within 10.
- We fix the problem before anything is disclosed, and agree a disclosure date with you.
- We credit you in the advisory unless you ask us not to.
- We publish a GitHub Security Advisory, with a CVE where one applies, when the fixed release is out.

## Scope

In scope:

- the plugin's endpoints (`/api/<collection>/passkeys/*`);
- session minting and revocation;
- challenge handling: single use, expiry and binding to the browser, user and collection;
- the admin components (the sign-in button, the Passkeys section and the enrolment prompt);
- the `passkeys:reset` command;
- the release pipeline: the GitHub workflows, npm trusted publishing and provenance.

Out of scope:

- Payload itself: report those to Payload through [its security policy](https://github.com/payloadcms/payload/security/policy);
- browsers, operating systems, passkey managers and authenticators;
- sites that ignore the README's guidance on CSRF (`csrf` or `serverURL`) or rate limiting (`rateLimit`), where the README describes the resulting weakness;
- the accepted limits the README lists under "Security model".

## Verifying releases

Every release is published by the repository's release workflow through npm trusted publishing, with a provenance attestation. To check what you installed, run `npm audit signatures` in your project, and on npmjs.com check that the version's **Provenance** names `The-Digital-Stride/payload-passkeys` and `.github/workflows/release.yml`. The README's "Verifying this package" section has the details.
