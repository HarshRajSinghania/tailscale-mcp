/**
 * Integration tests that hit the real Tailscale API.
 *
 * Gated behind RUN_INTEGRATION_TESTS=1 AND live credentials
 * (TAILSCALE_API_KEY or TAILSCALE_OAUTH_CLIENT_ID + TAILSCALE_OAUTH_CLIENT_SECRET).
 * Without the flag the entire suite is skipped -- so `npm test` in normal
 * development and PR CI remains fully offline. With the flag set but no
 * credentials the suite FAILS (see the credential-check describe below) instead
 * of skipping green.
 *
 * NOT read-only. Read this before choosing which tailnet to point it at:
 *
 *   - "Integration: real Tailscale API (read-only)" issues GETs only and is safe
 *     against any tailnet, production included.
 *   - "Integration: tailscale_create_key keyType=client round-trip" and its
 *     keyType=federated twin each MINT A REAL CREDENTIAL in the target tailnet
 *     (POST /tailnet/{tailnet}/keys) and delete it again in a `finally`. They sit
 *     behind the SAME RUN_INTEGRATION_TESTS=1 gate as the read-only suite, so the
 *     command below runs them too. If the process dies between create and delete,
 *     or the delete call fails, a live OAuth client / federated identity is left
 *     behind in that tailnet. Use a dedicated test tailnet, not production.
 *
 * Precondition: the target tailnet must have at least one device and at least one
 * key. Element-level shape drift is what this suite exists to catch, and an empty
 * tailnet would let every list assertion pass without inspecting a single field,
 * so the empty case fails loudly rather than passing silently.
 *
 * Run locally (bash):
 *   RUN_INTEGRATION_TESTS=1 TAILSCALE_API_KEY=tskey-api-... npm test
 *
 * There is no CI workflow for this suite (the repo runs no CI) -- run it
 * manually when you need API-shape-drift coverage.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const CREDENTIAL_VARS = ["TAILSCALE_API_KEY", "TAILSCALE_OAUTH_CLIENT_ID", "TAILSCALE_OAUTH_CLIENT_SECRET"];

const hasCredentials =
  !!process.env.TAILSCALE_API_KEY ||
  (!!process.env.TAILSCALE_OAUTH_CLIENT_ID && !!process.env.TAILSCALE_OAUTH_CLIENT_SECRET);

const optedIn = process.env.RUN_INTEGRATION_TESTS === "1";
const runIntegration = optedIn && hasCredentials;

type ApiResult<T> = {
  ok: boolean;
  status?: number;
  data?: T;
  rawBody?: string;
  etag?: string;
  error?: string;
};

// Minimal element shapes for the list assertions below. The fields are typed
// `unknown` on purpose: the tests assert the RUNTIME type, and declaring `string`
// here would let a live shape change type-check clean.
type DeviceElement = { id?: unknown; addresses?: unknown };
type KeyElement = { id?: unknown };

/**
 * RUN_INTEGRATION_TESTS=1 with a missing or misspelled credential variable used
 * to skip all three describes below and still report success. node:test does
 * print a `# SKIP` line per skipped suite, but the run summary counts skipped
 * TESTS, and the `it`s inside a skipped describe never register -- so the summary
 * an operator actually reads says `fail 0` AND `skipped 0` after zero live
 * requests were made. An explicit opt-in that degrades to a silent no-op is worse
 * than no opt-in at all, so fail here and name the variables that are unset.
 */
describe("Integration: opt-in without credentials", { skip: !(optedIn && !hasCredentials) }, () => {
  it("RUN_INTEGRATION_TESTS=1 requires live credentials", () => {
    const unset = CREDENTIAL_VARS.filter((name) => !process.env[name]).join(", ");
    assert.fail(
      `RUN_INTEGRATION_TESTS=1 is set but no live credentials were found (unset: ${unset}). ` +
        "Set TAILSCALE_API_KEY, or both TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET, " +
        "or unset RUN_INTEGRATION_TESTS to skip the integration suite.",
    );
  });
});

describe("Integration: real Tailscale API (read-only)", { skip: !runIntegration }, () => {
  it("tailscale_status returns tailnet, deviceCount, and connected flag", async () => {
    const { statusTools } = await import("./tools/status.js");
    const tool = statusTools.find((t) => t.name === "tailscale_status");
    assert.ok(tool, "tailscale_status tool not found");
    const handler = tool.handler as () => Promise<
      ApiResult<{
        connected: boolean;
        deviceCount: number;
        tailnet: string;
        settings?: unknown;
        errors?: Record<string, string>;
      }>
    >;
    const result = await handler();
    assert.equal(result.ok, true, `API call failed: ${result.error ?? "(no error)"}`);
    assert.equal(typeof result.data?.tailnet, "string");
    assert.equal(typeof result.data?.connected, "boolean");
    assert.equal(typeof result.data?.deviceCount, "number");
    // The handler fires /devices and /settings in parallel and only fast-fails
    // when BOTH fail, so a settings-only 404 / scope error / shape change still
    // returns ok:true and records itself in data.errors. Every assertion above is
    // devices-side (deviceCount already catches a devices-only failure), so
    // without this line a settings-side failure -- exactly the drift this suite
    // exists to catch -- was invisible. The errors bag is the handler's own drift
    // signal, and it was being discarded.
    assert.equal(result.data?.errors, undefined, JSON.stringify(result.data?.errors));
    // Settings-side counterpart to the deviceCount check: a 200 with an empty body
    // leaves settings null without populating errors. assert.ok, not
    // `typeof === "object"` -- typeof null is "object", so the typeof form would
    // pass on the very failure path it is meant to catch.
    assert.ok(result.data?.settings, "expected data.settings to be populated");
  });

  it("tailscale_list_devices returns devices with element shape intact", async () => {
    const { deviceTools } = await import("./tools/devices.js");
    const tool = deviceTools.find((t) => t.name === "tailscale_list_devices");
    assert.ok(tool, "tailscale_list_devices tool not found");
    const handler = tool.handler as (input: { fields?: string }) => Promise<ApiResult<{ devices?: DeviceElement[] }>>;
    const result = await handler({});
    assert.equal(result.ok, true, `API call failed: ${result.error ?? "(no error)"}`);
    const devices = result.data?.devices;
    assert.ok(Array.isArray(devices), "expected data.devices to be an array");
    // Array.isArray alone catches container-level drift (field rename, non-array)
    // but passes on an empty tailnet without ever touching an element -- and
    // element shape is precisely the drift fetch mocks cannot catch. Fail rather
    // than skip on empty: a skip reads in the summary as coverage that never ran.
    assert.ok(devices.length > 0, "expected at least one device -- this suite requires a non-empty test tailnet");
    const device = devices[0];
    assert.equal(typeof device.id, "string", `expected device.id to be a string, got ${typeof device.id}`);
    const addresses = device.addresses;
    assert.ok(Array.isArray(addresses), "expected device.addresses to be an array");
    assert.equal(typeof addresses[0], "string", "expected device.addresses[0] to be a string");
  });

  it("tailscale_list_keys (all=true) returns keys with element shape intact", async () => {
    const { keyTools } = await import("./tools/keys.js");
    const tool = keyTools.find((t) => t.name === "tailscale_list_keys");
    assert.ok(tool, "tailscale_list_keys tool not found");
    const handler = tool.handler as (input: { all?: boolean }) => Promise<ApiResult<{ keys?: KeyElement[] }>>;
    // all:true, not {} -- the default query sends no `all` parameter and so lists
    // auth keys only, which means the OAuth-client and federated-identity shapes
    // the round-trip describes below create were never in the body this test
    // inspected. A 403 here on the OAuth credential path means the client's scopes
    // do not cover the broader query: a permissions failure, not shape drift.
    const result = await handler({ all: true });
    assert.equal(result.ok, true, `API call failed: ${result.error ?? "(no error)"}`);
    const keys = result.data?.keys;
    assert.ok(Array.isArray(keys), "expected data.keys to be an array");
    // Same reasoning as the devices test: the container check passes on an empty
    // tailnet, so require an element and actually look at it.
    assert.ok(keys.length > 0, "expected at least one key -- this suite requires a tailnet with at least one key");
    const key = keys[0];
    assert.equal(typeof key.id, "string", `expected key.id to be a string, got ${typeof key.id}`);
  });

  it("tailscale_get_acl returns non-empty HuJSON body with ETag marker", async () => {
    const { aclTools } = await import("./tools/acl.js");
    const tool = aclTools.find((t) => t.name === "tailscale_get_acl");
    assert.ok(tool, "tailscale_get_acl tool not found");
    const handler = tool.handler as () => Promise<ApiResult<unknown>>;
    const result = await handler();
    assert.equal(result.ok, true, `API call failed: ${result.error ?? "(no error)"}`);
    assert.equal(typeof result.rawBody, "string");
    // The handler appends a five-line `// ETag:` footer to rawBody whenever the
    // response is ok and carries an ETag, so a bare `rawBody.length > 0` check was
    // satisfied by the handler's own footer and stayed green on an empty policy
    // body. Split at the footer and assert the part the live API actually sent.
    // Non-empty is the only structural claim made here: HuJSON policies commonly
    // open with a `//` comment block, so a `startsWith("{")` check would
    // false-fail on real tailnets.
    const body = (result.rawBody ?? "").split("\n// ETag:")[0].trim();
    assert.ok(body.length > 0, "expected non-empty ACL body before the ETag footer");
    // Kept as a live-API signal the mocked unit coverage cannot give: the unit test
    // hand-sets the etag response header, so it can never see a real API that
    // stops sending one (no header -> no footer -> this regex fails).
    assert.match(result.rawBody ?? "", /ETag:\s*\S+/);
    // The parsed field tailscale_update_acl actually consumes as If-Match; the
    // footer above is only a human-readable copy of it.
    assert.equal(typeof result.etag, "string");
  });
});

describe("Integration: tailscale_create_key keyType=client round-trip", { skip: !runIntegration }, () => {
  // MUTATES the target tailnet: mints a real OAuth client and deletes it again.
  // See the file header -- this runs under the same RUN_INTEGRATION_TESTS=1 gate
  // as the read-only suite above, so "safe against production" does not apply.
  it("creates an OAuth client key and immediately deletes it", async () => {
    const { keyTools } = await import("./tools/keys.js");

    const createTool = keyTools.find((t) => t.name === "tailscale_create_key");
    assert.ok(createTool, "tailscale_create_key tool not found");
    const createHandler = createTool.handler as (input: {
      keyType?: "auth" | "client" | "federated";
      description?: string;
      scopes?: string[];
      tags?: string[];
    }) => Promise<ApiResult<{ id?: string }>>;

    const deleteTool = keyTools.find((t) => t.name === "tailscale_delete_key");
    assert.ok(deleteTool, "tailscale_delete_key tool not found");
    const deleteHandler = deleteTool.handler as (input: { keyId: string }) => Promise<ApiResult<unknown>>;

    const createResult = await createHandler({
      keyType: "client",
      scopes: ["devices:read"],
      description: "ci-smoke-client",
    });
    const keyId = createResult.data?.id;

    try {
      assert.equal(
        createResult.ok,
        true,
        `tailscale_create_key (client) failed: ${createResult.error ?? "(no error)"}`,
      );
      assert.ok(keyId, "expected response data to contain an id");
    } finally {
      if (keyId) {
        const deleteResult = await deleteHandler({ keyId });
        assert.equal(
          deleteResult.ok,
          true,
          `tailscale_delete_key (client) failed: ${deleteResult.error ?? "(no error)"}`,
        );
      }
    }
  });
});

describe("Integration: tailscale_create_key keyType=federated round-trip", { skip: !runIntegration }, () => {
  // MUTATES the target tailnet: mints a real federated identity and deletes it
  // again. Same gate as above -- see the file header.
  it("creates a federated identity key and immediately deletes it", async () => {
    const { keyTools } = await import("./tools/keys.js");

    const createTool = keyTools.find((t) => t.name === "tailscale_create_key");
    assert.ok(createTool, "tailscale_create_key tool not found");
    const createHandler = createTool.handler as (input: {
      keyType?: "auth" | "client" | "federated";
      description?: string;
      scopes?: string[];
      issuer?: string;
      subject?: string;
      audience?: string;
    }) => Promise<ApiResult<{ id?: string }>>;

    const deleteTool = keyTools.find((t) => t.name === "tailscale_delete_key");
    assert.ok(deleteTool, "tailscale_delete_key tool not found");
    const deleteHandler = deleteTool.handler as (input: { keyId: string }) => Promise<ApiResult<unknown>>;

    const createResult = await createHandler({
      keyType: "federated",
      scopes: ["devices:read"],
      issuer: "https://token.actions.githubusercontent.com",
      subject: "repo:YawLabs/tailscale-mcp:ref:refs/heads/test-smoke-do-not-merge",
      audience: "sts.tailscale.com",
      description: "ci-smoke-fed",
    });
    const keyId = createResult.data?.id;

    try {
      assert.equal(
        createResult.ok,
        true,
        `tailscale_create_key (federated) failed: ${createResult.error ?? "(no error)"}`,
      );
      assert.ok(keyId, "expected response data to contain an id");
    } finally {
      if (keyId) {
        const deleteResult = await deleteHandler({ keyId });
        assert.equal(
          deleteResult.ok,
          true,
          `tailscale_delete_key (federated) failed: ${deleteResult.error ?? "(no error)"}`,
        );
      }
    }
  });
});

/**
 * The /acl/preview response shape, which tailscale_diff_acl_access depends on
 * entirely and which no unit test can verify: every fixture in handlers.test.ts
 * is a hand-written guess at the wire format, derived from the Go client's
 * ACLPreviewResponse / UserRuleMatch structs rather than from an observed
 * response.
 *
 * A POST, but read-only in effect: preview evaluates a policy and applies
 * nothing. The policy submitted here is the tailnet's OWN current policy, so
 * even a hypothetical server-side misroute could not change the effective
 * configuration.
 *
 * Two open questions are recorded via t.diagnostic() rather than asserted,
 * because the correct answer is unknown and asserting a guess is how a fixture
 * ends up pinning a shape the API never sends. Both gate documented blind spots
 * in tailscale_diff_acl_access -- see the `scope` string it returns and the
 * CHANGELOG entry. Run this suite to answer them:
 *
 *   1. Does the response carry a top-level `postures` map? If it does, and it
 *      holds the submitted policy's posture DEFINITIONS, the posture-definition
 *      blind spot becomes fixable: the diff could key on definitions instead of
 *      names, and a tightened `posture:corp` would stop reading as unchanged.
 *   2. Does a single `ports` entry ever carry a comma-joined port list
 *      ("tag:prod:22,80")? That is what makes a narrowed port range surface as a
 *      paired loss and gain of the whole entry rather than a clean loss.
 */
describe("Integration: ACL preview response shape", { skip: !runIntegration }, () => {
  it("returns a matches array whose elements carry the fields the diff keys on", async (t) => {
    const { aclTools } = await import("./tools/acl.js");
    const { userTools } = await import("./tools/users.js");

    const getAcl = aclTools.find((tool) => tool.name === "tailscale_get_acl");
    const listUsers = userTools.find((tool) => tool.name === "tailscale_list_users");
    assert.ok(getAcl, "tailscale_get_acl tool not found");
    assert.ok(listUsers, "tailscale_list_users tool not found");

    // Strip the ETag footer tailscale_get_acl appends: it is valid HuJSON, but
    // the baseline should be the policy as stored.
    const aclResult = (await (getAcl.handler as () => Promise<ApiResult<unknown>>)()) as ApiResult<unknown>;
    assert.equal(aclResult.ok, true, `could not read the ACL: ${aclResult.error ?? "(no error)"}`);
    const policy = (aclResult.rawBody ?? "").split("\n// ETag:")[0];
    assert.ok(policy.trim().length > 0, "expected a non-empty ACL body to preview against");

    const usersResult = (await (
      listUsers.handler as (
        input: Record<string, unknown>,
      ) => Promise<ApiResult<{ users?: Array<Record<string, unknown>> }>>
    )({})) as ApiResult<{ users?: Array<Record<string, unknown>> }>;
    assert.equal(usersResult.ok, true, `could not list users: ${usersResult.error ?? "(no error)"}`);
    const users = usersResult.data?.users ?? [];
    // Same precondition rationale as the device/key suites above: an empty
    // tailnet would let every assertion below pass without inspecting a field.
    assert.ok(users.length > 0, "target tailnet has no users; this suite cannot check the preview shape");

    // The field tailscale_diff_acl_access resolves principals from. If this is
    // ever not a string on a live tailnet, that tool's fallback chain is load
    // bearing and its blind-spot disclosure needs revisiting.
    const loginName = users[0]?.loginName;
    assert.equal(typeof loginName, "string", "expected users[].loginName to be a string on the live API");

    const preview = aclTools.find((tool) => tool.name === "tailscale_preview_acl");
    assert.ok(preview, "tailscale_preview_acl tool not found");
    const result = (await (
      preview.handler as (input: { policy: string; type: string; previewFor: string }) => Promise<ApiResult<unknown>>
    )({ policy, type: "user", previewFor: loginName as string })) as ApiResult<unknown>;
    assert.equal(result.ok, true, `preview failed: ${result.error ?? "(no error)"}`);

    // previewAccess parses rawBody itself rather than letting apiRequest do it,
    // so this mirrors that path exactly.
    const parsed = JSON.parse(result.rawBody ?? "") as {
      matches?: unknown;
      postures?: unknown;
      type?: unknown;
      previewFor?: unknown;
    };

    // The hard dependency: previewAccess treats an absent matches array as a
    // failure precisely so a shape change cannot read as "reaches nothing".
    assert.ok(Array.isArray(parsed.matches), `expected a matches array, got: ${JSON.stringify(parsed).slice(0, 400)}`);

    const matches = parsed.matches as Array<Record<string, unknown>>;
    for (const match of matches) {
      if (match.ports !== undefined) assert.ok(Array.isArray(match.ports), "ports must be an array when present");
      if (match.via !== undefined) assert.ok(Array.isArray(match.via), "via must be an array when present");
      if (match.postures !== undefined) {
        assert.ok(Array.isArray(match.postures), "match.postures must be an array of NAMES when present");
      }
    }

    // ---- Open question 1: the response-level postures map ----
    const posturesMap = parsed.postures;
    if (posturesMap === undefined) {
      t.diagnostic(
        "preview response has NO top-level `postures` map -- the posture-definition blind spot is unfixable from this response alone",
      );
    } else {
      t.diagnostic(`preview response HAS a top-level \`postures\` map: ${JSON.stringify(posturesMap).slice(0, 600)}`);
      t.diagnostic(
        "if that map holds the submitted policy's posture DEFINITIONS, the posture-definition blind spot in tailscale_diff_acl_access is fixable -- key on definitions, not names",
      );
    }

    // ---- Open question 2: comma-joined port lists ----
    const allPorts = matches.flatMap((m) => (Array.isArray(m.ports) ? (m.ports as unknown[]) : []));
    const commaJoined = allPorts.filter((p) => typeof p === "string" && p.includes(","));
    if (commaJoined.length > 0) {
      t.diagnostic(
        `ports entries DO carry comma-joined lists (e.g. ${JSON.stringify(commaJoined[0])}) -- confirms the narrowed-port-range blind spot is real`,
      );
    } else {
      t.diagnostic(
        `no comma-joined ports entry seen in ${allPorts.length} entries on this tailnet -- inconclusive, not proof the blind spot is absent`,
      );
    }
  });
});
