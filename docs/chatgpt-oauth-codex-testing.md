# ChatGPT OAuth and Codex integration — test notes

This branch is experimental. It keeps the existing API-key route intact and adds a separate ChatGPT account sign-in.

## 1. Get the branch and install dependencies (Windows)

From PowerShell, in a fresh clone of your fork:

```powershell
git fetch origin
git switch feature/chatgpt-oauth-codex
npm ci
npm ci --prefix app/desktop
```

Use Node.js 22.19 or newer. The desktop app's Electron dependency is installed by the second command.

## 2. Run the automated tests

From the repository root:

```powershell
npm test
```

This discovers the new OAuth and Codex tests automatically. The repository's Windows CI also runs the keystore tests against Windows Credential Manager on a real Windows runner.

## 3. Start NeverQuestAlone

```powershell
npm start
```

Open the AI/provider list and select the OpenAI / ChatGPT card. Choose **Sign in with ChatGPT**. The app should open the system browser, complete the OpenAI sign-in, return to the app, and select an OAuth-enabled model if the account is eligible.

The ChatGPT sign-in route is experimental. Plan availability for this open-source OAuth flow is determined by OpenAI; the app validates the direct-use scope and lists models it can see. A Go subscription does not guarantee that OpenAI will authorize this particular open-source app. The existing OpenAI API-key flow remains available as a fallback.

To test that an existing OAuth connection survives a restart, close and reopen the app, then choose **Use saved ChatGPT account** on the OpenAI card. It revalidates model access before switching.

## 4. Test Codex locally

Install the official Codex CLI first. On Windows, OpenAI documents this PowerShell installer:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://chatgpt.com/codex/install.ps1 | iex"
```

Then verify it is discoverable:

```powershell
codex --version
```

Restart NeverQuestAlone after installing the CLI so it inherits the updated PATH. On the connected ChatGPT card, click **Test Codex locally**.

The test launches `codex app-server` once, passes the saved access token only through the child process's `ACCESS_TOKEN` environment variable, creates a fresh temporary `CODEX_HOME` and empty workspace, and removes that temporary directory after the app-server exits. The Codex turn uses read-only access restricted to that empty workspace, with network access disabled for agent tools. The app-server itself still needs network access to OpenAI for the model request. This is a short usage-consuming request against the ChatGPT plan's Codex allowance.

This is a local app-server connectivity smoke test, **not yet a full Codex-agent replacement for the in-game companion**. Normal in-game responses still go through the OpenAI Responses API using ChatGPT-plan OAuth.

## 5. What to report if it fails

Please include the exact step that failed and the visible error line, but never paste access tokens, refresh tokens, ID tokens, or a full credential-store export.

- Browser returns but the app reports sign-in failure: confirm the browser completed the OpenAI approval page, then retry. The plan/account may not be eligible for this app's OAuth registration.
- Sign-in works but model validation fails: this account may not have direct-use Responses API access or may not have any models in the app's current catalog.
- Codex test says it is missing: check `codex --version` in the same Windows account and restart the app after installing.
- Codex test fails after starting: check that the locally installed CLI version supports `codex app-server`, and include its version in the report.

The CI workflow is expected to run on pushes and pull requests. If GitHub shows no Actions runs for this fork, enable Actions for the fork in GitHub's Actions tab and re-run the workflow.

## Upstream updates

Keep changes on this feature branch. When the fork's `main` is synced with upstream `tommygeoco/neverquestalone`, rebase this branch onto the updated `main`, resolve any conflicts, run the full test suite, and push the feature branch. Never apply experimental OAuth changes directly to `main`.
