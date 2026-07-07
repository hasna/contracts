import { describe, expect, test } from "bun:test";
import {
  COMMS_EVENT_TYPES,
  COMMS_SEVERITY_TAG_INFO,
  COMMS_SEVERITY_TAGS,
  CommsChannelMetadataSchema,
  CommsEventEnvelopeSchema,
  CommsEventTypeSchema,
  CommsMessageMetadataSchema,
  commsSeverityTagToken,
  defaultSeverityForCommsEventType,
  extractCommsSeverityTag,
  SCHEMA_IDS,
  validateCommsTaggedMessage,
  validateContract,
  validateEmbeddedContract
} from "../src";

const createdAt = "2026-07-06T10:00:00.000Z";

function envelope(overrides: Record<string, unknown> = {}) {
  return {
    schema: SCHEMA_IDS.commsEventEnvelope,
    id: "evt_test_1",
    createdAt,
    type: "release.published",
    severity: "info",
    scope: "fleet",
    dedupe_key: "release.published:@hasna/contracts@0.5.0",
    ...overrides
  };
}

function channelMetadata(overrides: Record<string, unknown> = {}) {
  return {
    schema: SCHEMA_IDS.commsChannelMetadata,
    id: "announcements",
    createdAt,
    class: "fleet",
    ...overrides
  };
}

function freezeEnvelope(overrides: Record<string, unknown> = {}) {
  return envelope({
    id: "evt_fleet_freeze_1",
    type: "fleet.freeze",
    severity: "critical",
    scope: "fleet",
    action_required: true,
    ack_by: "2026-07-06T12:00:00.000Z",
    dedupe_key: "fleet.freeze:2026-07-06:test",
    ...overrides
  });
}

function messageMetadata(overrides: Record<string, unknown> = {}) {
  return {
    schema: SCHEMA_IDS.commsMessageMetadata,
    id: "msg_test_1",
    createdAt,
    tag: "FREEZE",
    envelope: freezeEnvelope(),
    ...overrides
  };
}

type AnySafeParseResult =
  | { success: true }
  | { success: false; error: { issues: { path: (string | number)[] }[] } };

function issuePaths(result: AnySafeParseResult): string[] {
  return result.success ? [] : result.error.issues.map((issue) => issue.path.join(".")).sort();
}

describe("comms event envelope", () => {
  test("parses a minimal fleet-scoped event and applies defaults", () => {
    const parsed = CommsEventEnvelopeSchema.parse(envelope());
    expect(parsed.affected_packages).toEqual([]);
    expect(parsed.affected_machines).toEqual([]);
    expect(parsed.action_required).toBe(false);
    expect(parsed.resourceRefs).toEqual([]);
    expect(parsed.evidenceRefs).toEqual([]);
  });

  test("dedupe_key is mandatory and non-empty", () => {
    const { dedupe_key: _dropped, ...withoutKey } = envelope();
    expect(CommsEventEnvelopeSchema.safeParse(withoutKey).success).toBe(false);
    expect(CommsEventEnvelopeSchema.safeParse(envelope({ dedupe_key: "  " })).success).toBe(false);
  });

  test("rejects unknown keys (strict wire shape)", () => {
    expect(CommsEventEnvelopeSchema.safeParse(envelope({ urgent: true })).success).toBe(false);
  });

  test("package scope requires affected_packages", () => {
    const bad = CommsEventEnvelopeSchema.safeParse(envelope({ scope: "package" }));
    expect(issuePaths(bad)).toEqual(["affected_packages"]);
    const good = CommsEventEnvelopeSchema.safeParse(
      envelope({ scope: "package", affected_packages: ["@hasna/loops"] })
    );
    expect(good.success).toBe(true);
  });

  test("machine scope requires affected_machines", () => {
    const bad = CommsEventEnvelopeSchema.safeParse(envelope({ scope: "machine" }));
    expect(issuePaths(bad)).toEqual(["affected_machines"]);
    const good = CommsEventEnvelopeSchema.safeParse(envelope({ scope: "machine", affected_machines: ["spark01"] }));
    expect(good.success).toBe(true);
  });

  test("ack_by requires action_required", () => {
    const bad = CommsEventEnvelopeSchema.safeParse(envelope({ ack_by: "2026-07-07T10:00:00.000Z" }));
    expect(issuePaths(bad)).toEqual(["action_required"]);
    const good = CommsEventEnvelopeSchema.safeParse(
      envelope({ ack_by: "2026-07-07T10:00:00.000Z", action_required: true })
    );
    expect(good.success).toBe(true);
  });

  test("fleet.freeze and fleet.unfreeze pin critical + fleet scope + action_required", () => {
    expect(CommsEventEnvelopeSchema.safeParse(freezeEnvelope()).success).toBe(true);
    expect(
      CommsEventEnvelopeSchema.safeParse(freezeEnvelope({ type: "fleet.unfreeze", dedupe_key: "fleet.unfreeze:test" }))
        .success
    ).toBe(true);

    const wrong = CommsEventEnvelopeSchema.safeParse(
      freezeEnvelope({ severity: "notice", scope: "machine", affected_machines: ["spark01"], action_required: false, ack_by: undefined })
    );
    expect(issuePaths(wrong)).toEqual(["action_required", "scope", "severity"]);
  });

  test("event types must be 2-4 lowercase dot-separated segments", () => {
    expect(CommsEventTypeSchema.safeParse("fleet.freeze").success).toBe(true);
    expect(CommsEventTypeSchema.safeParse("comms.protocol.bumped").success).toBe(true);
    expect(CommsEventTypeSchema.safeParse("a.b.c.d").success).toBe(true);
    expect(CommsEventTypeSchema.safeParse("freeze").success).toBe(false);
    expect(CommsEventTypeSchema.safeParse("a.b.c.d.e").success).toBe(false);
    expect(CommsEventTypeSchema.safeParse("Fleet.Freeze").success).toBe(false);
    expect(CommsEventTypeSchema.safeParse("fleet..freeze").success).toBe(false);
    expect(CommsEventTypeSchema.safeParse("fleet.freeze ").success).toBe(false);
  });
});

describe("comms channel metadata", () => {
  test("accepts every channel class from the taxonomy", () => {
    for (const cls of ["fleet", "package", "product", "loop-lane", "initiative", "personal"]) {
      const value = channelMetadata(
        cls === "initiative" ? { class: cls, owner: "chief", until: "2026-08-01" } : { class: cls }
      );
      expect(CommsChannelMetadataSchema.safeParse(value).success).toBe(true);
    }
    expect(CommsChannelMetadataSchema.safeParse(channelMetadata({ class: "machine" })).success).toBe(false);
  });

  test("initiative channels require owner and until", () => {
    const bad = CommsChannelMetadataSchema.safeParse(channelMetadata({ class: "initiative" }));
    expect(issuePaths(bad)).toEqual(["owner", "until"]);
    const gateBound = CommsChannelMetadataSchema.safeParse(
      channelMetadata({ class: "initiative", owner: "chief", until: "gate:97610c99" })
    );
    expect(gateBound.success).toBe(true);
  });

  test("archived channels can carry a successor pointer, unknown keys rejected", () => {
    expect(CommsChannelMetadataSchema.safeParse(channelMetadata({ successor: "ops" })).success).toBe(true);
    expect(CommsChannelMetadataSchema.safeParse(channelMetadata({ members: ["chief"] })).success).toBe(false);
  });

  test("noise classes are quiet/work/firehose", () => {
    for (const noise of ["quiet", "work", "firehose"]) {
      expect(CommsChannelMetadataSchema.safeParse(channelMetadata({ noise })).success).toBe(true);
    }
    expect(CommsChannelMetadataSchema.safeParse(channelMetadata({ noise: "loud" })).success).toBe(false);
  });

  test("until horizons must be machine-evaluatable (date, timestamp, or gate id)", () => {
    const initiative = (until: string) => channelMetadata({ class: "initiative", owner: "chief", until });
    expect(CommsChannelMetadataSchema.safeParse(initiative("2026-08-01")).success).toBe(true);
    expect(CommsChannelMetadataSchema.safeParse(initiative("2026-08-01T12:00:00Z")).success).toBe(true);
    expect(CommsChannelMetadataSchema.safeParse(initiative("gate:97610c99")).success).toBe(true);
    expect(
      CommsChannelMetadataSchema.safeParse(initiative("gate:97610c99-aaaa-bbbb-cccc-dddddddddddd")).success
    ).toBe(true);
    for (const bad of ["soon", "next quarter", "gate:", "gate:xyz", "08/01/2026"]) {
      const result = CommsChannelMetadataSchema.safeParse(initiative(bad));
      expect(result.success).toBe(false);
      expect(issuePaths(result)).toEqual(["until"]);
    }
  });
});

describe("comms message metadata", () => {
  test("accepts a matching tag + envelope", () => {
    expect(CommsMessageMetadataSchema.safeParse(messageMetadata()).success).toBe(true);
  });

  test("bounds severity per tag", () => {
    const bad = CommsMessageMetadataSchema.safeParse(
      messageMetadata({
        tag: "RELEASE",
        envelope: envelope({ severity: "breaking" })
      })
    );
    expect(bad.success).toBe(false);
    if (!bad.success) {
      expect(bad.error.issues.map((issue) => issue.path.join("."))).toContain("envelope.severity");
    }
  });

  test("FREEZE/UNFREEZE tags pin their event type both directions", () => {
    const wrongType = CommsMessageMetadataSchema.safeParse(
      messageMetadata({ tag: "FREEZE", envelope: envelope({ severity: "critical" }) })
    );
    expect(wrongType.success).toBe(false);
    if (!wrongType.success) {
      expect(wrongType.error.issues.map((issue) => issue.path.join("."))).toContain("envelope.type");
    }

    const wrongTag = CommsMessageMetadataSchema.safeParse(messageMetadata({ tag: "CUTOVER" }));
    expect(wrongTag.success).toBe(false);
    if (!wrongTag.success) {
      expect(wrongTag.error.issues.map((issue) => issue.path.join("."))).toContain("tag");
    }
  });
});

describe("severity mapping table", () => {
  test("covers the strategy's event types with the ruled severities", () => {
    expect(defaultSeverityForCommsEventType("release.published")).toBe("info");
    expect(defaultSeverityForCommsEventType("release.breaking")).toBe("breaking");
    expect(defaultSeverityForCommsEventType("config.changed")).toBe("notice");
    expect(defaultSeverityForCommsEventType("comms.protocol.bumped")).toBe("breaking");
    expect(defaultSeverityForCommsEventType("incident.opened")).toBe("critical");
    expect(defaultSeverityForCommsEventType("incident.resolved")).toBe("notice");
    expect(defaultSeverityForCommsEventType("cloud.cutover.step")).toBe("notice");
    expect(defaultSeverityForCommsEventType("fleet.freeze")).toBe("critical");
    expect(defaultSeverityForCommsEventType("fleet.unfreeze")).toBe("critical");
    expect(defaultSeverityForCommsEventType("fleet.directive")).toBe("notice");
    expect(defaultSeverityForCommsEventType("made.up.type")).toBeNull();
  });

  test("every mapped event type is a valid namespaced type and tag defaults stay in bounds", () => {
    for (const [type, info] of Object.entries(COMMS_EVENT_TYPES)) {
      expect(CommsEventTypeSchema.safeParse(type).success).toBe(true);
      if (info.tag) {
        const tagInfo = COMMS_SEVERITY_TAG_INFO[info.tag];
        expect(tagInfo.allowedSeverities).toContain(info.defaultSeverity);
      }
    }
  });

  test("tag table stays aligned with the tag enum", () => {
    expect(Object.keys(COMMS_SEVERITY_TAG_INFO).sort()).toEqual([...COMMS_SEVERITY_TAGS].sort());
    for (const info of Object.values(COMMS_SEVERITY_TAG_INFO)) {
      expect(info.allowedSeverities).toContain(info.defaultSeverity);
    }
  });

  test("tag <-> event-type pins are a bijection across both tables", () => {
    // Every tag that pins an event type must be that event type's tag...
    for (const [tag, info] of Object.entries(COMMS_SEVERITY_TAG_INFO)) {
      if (info.requiredEventType) {
        expect(COMMS_EVENT_TYPES[info.requiredEventType]?.tag).toBe(tag as (typeof COMMS_SEVERITY_TAGS)[number]);
      }
    }
    // ...and every event type whose tag pins a type must pin back to itself.
    for (const [type, info] of Object.entries(COMMS_EVENT_TYPES)) {
      if (info.tag) {
        const pinned = COMMS_SEVERITY_TAG_INFO[info.tag].requiredEventType;
        if (pinned) {
          expect(pinned).toBe(type);
        }
      }
    }
    // The envelope-level hard pins cover exactly the tag-table pins.
    const pinnedTypes = Object.values(COMMS_SEVERITY_TAG_INFO)
      .map((info) => info.requiredEventType)
      .filter((type): type is string => type !== null)
      .sort();
    expect(pinnedTypes).toEqual(["fleet.freeze", "fleet.unfreeze"]);
  });
});

describe("severity tag extraction", () => {
  test("extracts exact-case first-token tags only", () => {
    expect(extractCommsSeverityTag("[FREEZE] halt publishes")).toBe("FREEZE");
    expect(extractCommsSeverityTag("  [UNFREEZE] resume")).toBe("UNFREEZE");
    expect(extractCommsSeverityTag("[BREAKING]\nloops 0.4 drops --once")).toBe("BREAKING");
    expect(extractCommsSeverityTag("[RELEASE]")).toBe("RELEASE");
    expect(extractCommsSeverityTag("[freeze] lowercase")).toBeNull();
    expect(extractCommsSeverityTag("[Freeze] mixed case")).toBeNull();
    expect(extractCommsSeverityTag("heads up [FREEZE] mid-text")).toBeNull();
    expect(extractCommsSeverityTag("[FREEZE]: colon glued")).toBeNull();
    expect(extractCommsSeverityTag("FREEZE no brackets")).toBeNull();
    expect(extractCommsSeverityTag("")).toBeNull();
  });

  test("renders tag tokens", () => {
    expect(commsSeverityTagToken("FREEZE")).toBe("[FREEZE]");
  });
});

describe("validateCommsTaggedMessage", () => {
  test("accepts a tagged post whose metadata matches", () => {
    const result = validateCommsTaggedMessage({
      text: "[FREEZE] halt publish/deploy during conversations cutover",
      metadata: messageMetadata()
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.tag).toBe("FREEZE");
      expect(result.metadata.envelope.type).toBe("fleet.freeze");
    }
  });

  test("rejects untagged or mis-tagged text", () => {
    const untagged = validateCommsTaggedMessage({ text: "please freeze", metadata: messageMetadata() });
    expect(untagged.success).toBe(false);
    if (!untagged.success) {
      expect(untagged.tag).toBeNull();
      expect(untagged.issues[0]?.path).toEqual(["text"]);
    }
  });

  test("rejects metadata that fails the schema", () => {
    const result = validateCommsTaggedMessage({
      text: "[FREEZE] halt",
      metadata: messageMetadata({ envelope: freezeEnvelope({ dedupe_key: undefined }) })
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.tag).toBe("FREEZE");
      expect(result.issues.length).toBeGreaterThan(0);
    }
  });

  test("rejects text/metadata tag mismatch", () => {
    const result = validateCommsTaggedMessage({
      text: "[UNFREEZE] resume",
      metadata: messageMetadata()
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.tag).toBe("UNFREEZE");
      expect(result.issues[0]?.path).toEqual(["tag"]);
    }
  });
});

describe("registry integration", () => {
  test("comms schemas dispatch through validateContract and validateEmbeddedContract", () => {
    expect(validateContract(SCHEMA_IDS.commsEventEnvelope, envelope()).success).toBe(true);
    expect(validateContract(SCHEMA_IDS.commsChannelMetadata, channelMetadata()).success).toBe(true);
    expect(validateContract(SCHEMA_IDS.commsMessageMetadata, messageMetadata()).success).toBe(true);

    const embedded = validateEmbeddedContract(messageMetadata());
    expect(embedded.success).toBe(true);
    if (embedded.success) {
      expect(embedded.schemaId).toBe(SCHEMA_IDS.commsMessageMetadata);
    }
  });
});
