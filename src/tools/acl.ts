import { z } from "zod";
import { apiGet, apiPost, getTailnet } from "../api.js";

// Default number of principals tailscale_diff_acl_access will preview. Each one
// costs TWO preview calls (baseline + proposed), so this is a request-count cap
// as much as a size cap: 25 principals is 50 requests, which is already enough
// to matter under TAILSCALE_MAX_CONCURRENT and the per-request budget.
const DEFAULT_PRINCIPAL_CAP = 25;

/** One rule match as the preview endpoint returns it (Go: UserRuleMatch). */
interface UserRuleMatch {
  users?: string[];
  ports?: string[];
  lineNumber?: number;
  via?: string[];
  postures?: string[];
}

/**
 * Reduce a preview response's matches to the set of things the principal can
 * actually REACH, as readable strings ("tag:prod:22", "10.0.0.1:443 via
 * tag:relay").
 *
 * Two fields present in the response are deliberately NOT part of the key, and
 * both would otherwise manufacture false positives on a tool whose entire job
 * is to be believed:
 *
 * - `lineNumber` is the rule's position in the policy text. Re-indenting a
 *   policy, or inserting a comment near the top, moves every subsequent rule
 *   and would report the whole tailnet as losing and re-gaining all access.
 * - `users` is the matched rule's SOURCE set. Narrowing `src: ["a", "b"]` to
 *   `src: ["a"]` leaves a's reachable destinations identical, but keying on it
 *   would show a as both losing and gaining the same access.
 *
 * What remains -- destination ports, plus the `via` and posture constraints
 * attached to reaching them -- is the answer to "what can this principal get
 * to, and under what conditions", which is the question being asked.
 *
 * A match carrying no ports contributes nothing: it grants no enumerable
 * destination, so there is nothing to gain or lose.
 */
function accessSet(matches: UserRuleMatch[]): Set<string> {
  const out = new Set<string>();
  for (const match of matches) {
    const via = [...(match.via ?? [])].sort();
    const postures = [...(match.postures ?? [])].sort();
    const qualifier = `${via.length > 0 ? ` via ${via.join(",")}` : ""}${
      postures.length > 0 ? ` posture ${postures.join(",")}` : ""
    }`;
    for (const port of match.ports ?? []) out.add(`${port}${qualifier}`);
  }
  return out;
}

/**
 * Run the preview endpoint for one principal against one policy and return its
 * access set, or an error string.
 *
 * Request headers deliberately mirror tailscale_preview_acl exactly (raw HuJSON
 * body, `Accept: application/hujson`, acceptRaw) rather than letting apiRequest
 * JSON-parse the response. The body still IS json, so it is parsed here -- but
 * owning the parse means a malformed or unexpected response surfaces as a named
 * failure for that principal instead of an empty match list, which on this tool
 * would render as "loses all access" and is the single worst way it could lie.
 */
async function previewAccess(
  policy: string,
  principal: string,
): Promise<{ ok: true; access: Set<string> } | { ok: false; error: string; status: number }> {
  const params = new URLSearchParams({ type: "user", previewFor: principal });
  const res = await apiPost(`/tailnet/${getTailnet()}/acl/preview?${params}`, undefined, {
    rawBody: policy,
    contentType: "application/hujson",
    acceptRaw: true,
    accept: "application/hujson",
  });
  // `status` is carried out so the caller can tell a principal-specific failure
  // from a blanket one: a 401/403 will refuse every remaining principal too, and
  // continuing would fire 2N doomed requests and stack one full multi-line auth
  // diagnostic per principal into the payload.
  if (!res.ok) return { ok: false, error: res.error || `HTTP ${res.status}`, status: res.status };

  let parsed: { matches?: UserRuleMatch[] };
  try {
    parsed = JSON.parse(res.rawBody ?? "") as { matches?: UserRuleMatch[] };
  } catch {
    return {
      ok: false,
      error: "the preview response was not valid JSON, so its rules could not be compared",
      status: res.status,
    };
  }
  // An absent `matches` key is NOT an empty rule set. A response shape change
  // would otherwise read as "this principal can reach nothing", i.e. a fake
  // total-revocation finding on every principal at once.
  if (!Array.isArray(parsed.matches)) {
    return {
      ok: false,
      error: "the preview response contained no `matches` array, so its rules could not be compared",
      status: res.status,
    };
  }
  return { ok: true, access: accessSet(parsed.matches) };
}

// First-line marker of the ETag footer tailscale_get_acl appends. The appender
// and stripEtagFooter both key off this one constant, so rewording the guidance
// lines cannot orphan a footer block an earlier release already wrote into a
// stored policy.
const ETAG_FOOTER_MARKER = "// ETag: ";

// Remove any ETag footer a previous tailscale_get_acl appended to an ACL body.
// Walks back over the trailing run of blank and `//` lines only -- the footer
// is only ever appended at the very end -- so comments belonging to the policy
// itself are left alone, and several stacked blocks come off in one pass.
function stripEtagFooter(body: string): string {
  const lines = body.split("\n");
  let cut = lines.length;
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (line === "") continue;
    if (!line.startsWith("//")) break;
    if (line.startsWith(ETAG_FOOTER_MARKER)) cut = i;
  }
  return lines.slice(0, cut).join("\n");
}

export const aclTools = [
  {
    name: "tailscale_get_acl",
    description:
      "Get the current ACL policy for your tailnet. Returns the raw policy text with original formatting preserved, including comments and trailing commas (HuJSON). Also returns an ETag — you must pass it to tailscale_update_acl to safely update the policy.",
    annotations: {
      title: "Get ACL policy",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: z.object({}),
    handler: async () => {
      const res = await apiGet(`/tailnet/${getTailnet()}/acl`, {
        acceptRaw: true,
        accept: "application/hujson",
      });
      if (res.ok && res.etag) {
        // Embed the ETag as a HuJSON `//` comment so the body remains valid HuJSON.
        // Earlier versions used a `---` separator + bare `ETag:` line, which 400'd
        // the API if an agent round-tripped rawBody verbatim into tailscale_update_acl.
        const footer = [
          "",
          `${ETAG_FOOTER_MARKER}${res.etag}`,
          "// Pass this ETag to tailscale_update_acl when updating the policy.",
          "// (HuJSON treats // as a comment — safe to leave in or strip before re-submitting.)",
          "",
        ].join("\n");
        // Strip the footer from an earlier get before stamping the current one.
        // tailscale_update_acl tells the agent to pass the full text back, so the
        // stored policy returns carrying the last footer; appending unconditionally
        // stacked one more block per edit cycle and grew the live ACL without bound.
        return { ...res, rawBody: `${stripEtagFooter(res.rawBody ?? "")}${footer}` };
      }
      return res;
    },
  },
  {
    name: "tailscale_update_acl",
    description:
      "Update the ACL policy for your tailnet. Accepts the full policy as a string to preserve formatting, comments, and trailing commas (HuJSON). You MUST pass the ETag from tailscale_get_acl to prevent overwriting concurrent changes. Always get the current ACL first, make targeted edits to the text, and pass the full modified text back.",
    annotations: {
      title: "Update ACL policy",
      readOnlyHint: false,
      // Overwrites the whole policy file in one call, and a bad push can lock
      // every device out of the tailnet -- the widest blast radius of any write
      // here, so clients must gate it rather than auto-approve it.
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: z.object({
      policy: z
        .string()
        .describe(
          "The full ACL policy text. Preserve existing formatting, comments, and structure. Only modify the specific parts that need to change.",
        ),
      etag: z
        .string()
        .trim()
        .min(1, "etag must not be empty -- an empty ETag would send this overwrite with no concurrency guard.")
        .describe("The ETag from tailscale_get_acl. Required to prevent concurrent edit conflicts."),
    }),
    // `.trim().min(1)`, not a bare `z.string()`: apiRequest sets If-Match behind
    // `if (options?.ifMatch)`, so an empty etag is falsy there and the header is
    // omitted entirely -- the write then overwrites a concurrent admin edit instead
    // of coming back 412, on the widest-blast-radius write in the package, with
    // no diagnostic anywhere. `.trim()` is load-bearing for the same reason it is
    // on tailnets.ts's ids: a bare `.min(1)` accepts " ", which is truthy, so the
    // header goes out carrying a precondition that cannot match any real ETag --
    // a confusing 412 instead of a local validation error naming the field.
    handler: async (input: { policy: string; etag: string }) => {
      return apiPost(`/tailnet/${getTailnet()}/acl`, undefined, {
        rawBody: input.policy,
        contentType: "application/hujson",
        ifMatch: input.etag,
        acceptRaw: true,
        accept: "application/hujson",
      });
    },
  },
  {
    name: "tailscale_validate_acl",
    description:
      "Validate an ACL policy without applying it. Returns any errors found, or confirms the policy is valid.",
    annotations: {
      title: "Validate ACL policy",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: z.object({
      policy: z.string().describe("The full ACL policy text to validate"),
    }),
    handler: async (input: { policy: string }) => {
      const res = await apiPost(`/tailnet/${getTailnet()}/acl/validate`, undefined, {
        rawBody: input.policy,
        contentType: "application/hujson",
        acceptRaw: true,
        accept: "application/hujson",
      });
      // Tailscale's validate endpoint returns 200 with either an empty body
      // or `{}` for a VALID policy; an object with a `message` / `error`
      // field for an INVALID one. Previously only the empty-body case was
      // normalized to "ACL policy is valid.", so a `{}` response leaked
      // through verbatim and looked like a diagnostic to the agent. Matches
      // cli.ts's parseValidationError treatment.
      if (res.ok) {
        const trimmed = res.rawBody?.trim();
        if (!trimmed || trimmed === "{}") {
          return { ...res, rawBody: "ACL policy is valid." };
        }
      }
      return res;
    },
  },
  {
    name: "tailscale_preview_acl",
    description:
      "Preview the ACL rules that would apply to a specific user or IP address if a proposed policy were applied.",
    annotations: {
      title: "Preview ACL rules",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: z.object({
      policy: z.string().describe("The proposed ACL policy text to preview"),
      type: z
        .enum(["user", "ipport"])
        .describe("Preview type: 'user' to see rules for a user, 'ipport' to see rules for an IP"),
      previewFor: z
        .string()
        .describe("The user email (for type 'user') or IP:port (for type 'ipport') to preview rules for"),
    }),
    handler: async (input: { policy: string; type: "user" | "ipport"; previewFor: string }) => {
      const params = new URLSearchParams({ type: input.type, previewFor: input.previewFor });
      return apiPost(`/tailnet/${getTailnet()}/acl/preview?${params}`, undefined, {
        rawBody: input.policy,
        contentType: "application/hujson",
        acceptRaw: true,
        accept: "application/hujson",
      });
    },
  },
  {
    name: "tailscale_diff_acl_access",
    description:
      "Answer 'who loses access?' before applying an ACL change. Compares the CURRENT policy against a proposed one and reports, per user, which destinations they gain and lose. Run this before tailscale_update_acl -- validate_acl only checks syntax and the policy's own tests block, so a policy with no tests validates clean while revoking everyone. " +
      "LIMITS, all reported in the response rather than left to be discovered. It compares USER principals only, so a revocation that runs through a tag or group can show a clean diff; it does not detect a change to a posture DEFINITION, because the comparison keys on posture names; and a narrowed port list shows as a paired loss and gain of the whole entry rather than a clean loss. An empty result is never proof a change is safe. It costs two preview requests per user, so it checks the first 25 by default and sets `truncated` with the counts. Users whose preview fails are listed in `failed` and excluded from the compared count -- a failure is never reported as lost access, and if nothing could be compared the call fails rather than returning an empty diff.",
    annotations: {
      title: "Diff ACL access",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: z.object({
      policy: z.string().describe("The proposed ACL policy text to compare against the current live policy"),
      principals: z
        .array(z.string().trim().min(1))
        .optional()
        .describe(
          "User emails to check. Omit to enumerate the tailnet's users automatically. Pass an explicit list to bound the request count, or to check specific users beyond the cap.",
        ),
      maxPrincipals: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(
          `Maximum users to check (default ${DEFAULT_PRINCIPAL_CAP}). Each costs two preview requests. Raising this on a large tailnet can be slow and may hit rate limits.`,
        ),
    }),
    handler: async (input: { policy: string; principals?: string[]; maxPrincipals?: number }) => {
      // Baseline is fetched directly rather than through tailscale_get_acl so it
      // arrives without that tool's appended ETag footer. (Comments are inert to
      // the preview endpoint either way, but the baseline should be the policy
      // as stored, not as decorated for an agent.)
      const current = await apiGet<unknown>(`/tailnet/${getTailnet()}/acl`, {
        acceptRaw: true,
        accept: "application/hujson",
      });
      if (!current.ok) {
        return {
          ok: false,
          error: `could not read the current ACL to diff against: ${current.error || `HTTP ${current.status}`}`,
        };
      }
      const baselinePolicy = current.rawBody ?? "";

      let principals: string[];
      let availableTotal: number;
      if (input.principals && input.principals.length > 0) {
        principals = [...new Set(input.principals)];
        availableTotal = principals.length;
      } else {
        const usersRes = await apiGet<{ users?: Array<Record<string, unknown>> }>(`/tailnet/${getTailnet()}/users`);
        if (!usersRes.ok) {
          return { ok: false, error: `could not list users to diff: ${usersRes.error || `HTTP ${usersRes.status}`}` };
        }
        // `loginName` is the documented login-email field, but the fallbacks are
        // deliberate: this tool is useless if a field rename empties the
        // principal list, and an empty list would otherwise read as "nobody is
        // affected". If none of these resolve, the error below says to pass
        // `principals` explicitly rather than returning a falsely clean diff.
        const emails = (usersRes.data?.users ?? [])
          .map((u) => u.loginName ?? u.email ?? u.name)
          .filter((v): v is string => typeof v === "string" && v.trim().length > 0);
        principals = [...new Set(emails)];
        availableTotal = principals.length;
        if (principals.length === 0) {
          return {
            ok: false,
            error:
              "no user emails could be read from the tailnet's user list, so there is nothing to compare. Pass `principals` explicitly with the emails to check -- an empty diff here would wrongly suggest the change affects nobody.",
          };
        }
      }

      const cap = input.maxPrincipals ?? DEFAULT_PRINCIPAL_CAP;
      const checked = principals.slice(0, cap);

      const changed: Array<{ principal: string; lost: string[]; gained: string[] }> = [];
      const unchanged: string[] = [];
      const failed: Array<{ principal: string; error: string }> = [];

      // One principal at a time, its two previews in parallel. Fanning all of
      // them out at once would put 2N requests in flight (50 at the default
      // cap) against a tailnet whose TAILSCALE_MAX_CONCURRENT is unset by
      // default -- a read-only diagnostic should not be the thing that trips
      // rate limiting on a tailnet its caller is about to reconfigure.
      for (const principal of checked) {
        const [before, after] = await Promise.all([
          previewAccess(baselinePolicy, principal),
          previewAccess(input.policy, principal),
        ]);
        // Both halves must succeed. With only one, the comparison is undefined
        // -- treating a failed proposed-preview as "reaches nothing" would
        // invent a total revocation, and the reverse would hide a real one.
        if (!before.ok || !after.ok) {
          // The outer guard is what narrows before/after to successes below it;
          // the ternary chain narrows each arm to the failing side, so its error
          // and status are readable without a cast. The trailing `undefined` arm
          // is unreachable given the guard, hence the `?.` rather than a
          // non-null assertion.
          const failure = !before.ok ? before : !after.ok ? after : undefined;
          const which = !before.ok ? "current" : "proposed";
          failed.push({
            principal,
            error: `preview against the ${which} policy failed: ${failure?.error ?? "unknown"}`,
          });
          // A 401/403 is not principal-specific: the credential has been refused
          // and every remaining preview will be refused too. Continuing would
          // fire the rest of the 2N requests against an API that has already
          // said no, and stack one full multi-line auth diagnostic per
          // principal into the payload. Stop and report the auth failure once.
          if (failure?.status === 401 || failure?.status === 403) {
            return {
              ok: false,
              error: `authentication failed while previewing ${principal}, so the diff was abandoned rather than continued against a credential the API has already refused: ${failure?.error ?? "unknown"}`,
            };
          }
          continue;
        }
        const lost = [...before.access].filter((a) => !after.access.has(a)).sort();
        const gained = [...after.access].filter((a) => !before.access.has(a)).sort();
        if (lost.length === 0 && gained.length === 0) unchanged.push(principal);
        else changed.push({ principal, lost, gained });
      }

      // The denominator is the number actually COMPARED, not attempted. Using
      // the attempted count meant a run where previews failed still opened with
      // "0 of 25 users checked lose access" -- the clause a reader is most
      // likely to quote -- while asserting coverage of users the tool never
      // compared. The tool's own description promised failures were excluded
      // from the counts; this is what makes that true.
      const compared = checked.length - failed.length;
      // Comparing nobody is not a clean diff. Every other zero-information
      // outcome here is already a hard error (unreadable ACL, unresolvable
      // emails); this is the same shape and the most reassuring-looking one.
      if (compared === 0 && checked.length > 0) {
        return {
          ok: false,
          error: `no users could be compared: all ${checked.length} preview attempts failed. First failure: ${failed[0]?.error ?? "unknown"}`,
        };
      }

      const losing = changed.filter((c) => c.lost.length > 0).length;
      const gaining = changed.filter((c) => c.gained.length > 0).length;
      const truncated = principals.length > checked.length;
      const summary = [
        // Failures lead when present, so the headline cannot read as an
        // all-clear over a partially-compared run.
        failed.length > 0 ? `${failed.length} of ${checked.length} users could not be checked` : null,
        `${losing} of ${compared} users compared lose access`,
        `${gaining} gain access`,
        `${unchanged.length} unchanged`,
        truncated ? `${principals.length - checked.length} not checked (cap ${cap})` : null,
      ]
        .filter(Boolean)
        .join(", ");

      return {
        ok: true,
        data: {
          tailnet: getTailnet(),
          summary,
          // Three numbers, because two of them were being conflated. `Compared`
          // is the only one that describes work actually done.
          principalsCompared: compared,
          principalsFailed: failed.length,
          principalsAvailable: availableTotal,
          truncated,
          // Restated in the payload, not just the tool description: whoever
          // reads this output is deciding whether to apply the change, and may
          // never have read the description. Each clause names a way this diff
          // can come back empty while real access changed.
          scope: [
            "User principals only.",
            "Not compared: access granted via tags or groups;",
            "changes to a posture DEFINITION (the diff keys on posture names, so redefining `posture:corp` more strictly leaves every key identical);",
            "and a destination whose port list is narrowed appears as a paired loss and gain of the whole entry (`tag:prod:22,80` -> `tag:prod:22`) rather than a clean loss, so `gained` is not a literal list of newly-reachable destinations.",
            "An empty diff is not proof the change is safe.",
          ].join(" "),
          changed,
          unchanged,
          failed,
        },
      };
    },
  },
] as const;
