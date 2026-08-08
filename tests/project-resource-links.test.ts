import { describe, expect, test } from "bun:test";
import {
  ContractSchemaRegistry,
  type ProjectResourceLink,
  type ProjectResourceLinkCollectionV1,
  ProjectResourceLinkCollectionV1Schema,
  ProjectResourceLinkInputSchema,
  ProjectResourceLinkLabelsSchema,
  ProjectResourceLinkLocatorSchema,
  ProjectResourceLinkSchema,
  ProjectResourceTargetKindSchema,
  ProjectResourceAuthoritySchema,
  SCHEMA_IDS,
  validateEmbeddedContract
} from "../src";

const projectId = "wks_sZFWdDF-W48787v3yoK29";
const createdAt = "2026-08-08T18:00:00.000Z";
const updatedAt = "2026-08-08T18:05:00.000Z";

const validInputs = [
  {
    authority: "todos",
    service_instance: "urn:hasna:todos:service:primary",
    source_package: "@hasna/todos",
    target_kind: "project",
    locator: { kind: "canonical_uri", value: "urn:hasna:todos:project:434a687f-6d99-4896-b260-7dc51538056a" },
    scope: "collection",
    labels: { name: "Dubai", tags: ["migration", " migration ", "", "resource-link"] }
  },
  {
    authority: "todos",
    service_instance: "https://todos.example.test",
    source_package: "@hasna/todos",
    target_kind: "task_list",
    locator: { kind: "external_uuid", value: "8DAF8A46-6993-57C0-ABE6-7E01763E18AF" },
    scope: "collection"
  },
  {
    authority: "todos",
    service_instance: "urn:hasna:todos:service:primary",
    source_package: "@hasna/todos",
    target_kind: "plan",
    locator: { kind: "canonical_uri", value: "https://todos.example.test/plans/dubai-rollout" },
    scope: "resource"
  },
  {
    authority: "todos",
    service_instance: "urn:hasna:todos:service:primary",
    source_package: "@hasna/todos",
    target_kind: "task",
    locator: { kind: "external_uuid", value: "E2F791BD-F26B-4FAC-A762-2CBA96202AA5" },
    scope: "resource"
  },
  {
    authority: "conversations",
    service_instance: "urn:hasna:conversations:service:primary",
    source_package: "@hasna/conversations",
    target_kind: "project",
    locator: { kind: "canonical_uri", value: "urn:hasna:conversations:project:dubai" },
    scope: "resource"
  },
  {
    authority: "conversations",
    service_instance: "urn:hasna:conversations:service:primary",
    source_package: "@hasna/conversations",
    target_kind: "channel",
    locator: { kind: "conversations_channel_id", value: "chn_79fa9c68937a1d020d6031dcaa3dd8d7" },
    scope: "collection",
    labels: { channel_name: "dubai" }
  },
  {
    authority: "knowledge",
    service_instance: "urn:hasna:knowledge:service:primary",
    source_package: "@hasna/knowledge",
    target_kind: "collection",
    locator: { kind: "canonical_uri", value: "urn:hasna:knowledge:collection:dubai" },
    scope: "collection"
  },
  {
    authority: "knowledge",
    service_instance: "urn:hasna:knowledge:service:primary",
    source_package: "@hasna/knowledge",
    target_kind: "item",
    locator: { kind: "external_uuid", value: "B4629725-8D32-4F24-A211-327FBD3D3A54" },
    scope: "resource"
  },
  {
    authority: "mementos",
    service_instance: "https://mementos.example.test",
    source_package: "@hasna/mementos",
    target_kind: "project",
    locator: { kind: "canonical_uri", value: "https://mementos.example.test/projects/dubai" },
    scope: "collection"
  },
  {
    authority: "mementos",
    service_instance: "urn:hasna:mementos:service:primary",
    source_package: "@hasna/mementos",
    target_kind: "item",
    locator: { kind: "canonical_uri", value: "urn:hasna:mementos:item:memento-dubai" },
    scope: "resource"
  },
  {
    authority: "orgs",
    service_instance: "urn:hasna:orgs:service:primary",
    source_package: "@hasna/orgs",
    target_kind: "org",
    locator: { kind: "canonical_uri", value: "urn:hasna:orgs:org:hasna" },
    scope: "collection"
  },
  {
    authority: "orgs",
    service_instance: "urn:hasna:orgs:service:primary",
    source_package: "@hasna/orgs",
    target_kind: "project",
    locator: { kind: "external_uuid", value: "7F2E67C5-C883-47DA-87DE-090C8F0A7F35" },
    scope: "resource"
  },
  {
    authority: "contacts",
    service_instance: "urn:hasna:contacts:service:primary",
    source_package: "@hasna/contacts",
    target_kind: "contact",
    locator: { kind: "external_uuid", value: "6B68E131-ABE5-43B7-92CD-9930B04611DF" },
    scope: "resource"
  }
] as const;

function persistedLink(input: (typeof validInputs)[number], index: number): ProjectResourceLink {
  const parsed = ProjectResourceLinkInputSchema.parse(input);
  return ProjectResourceLinkSchema.parse({
    ...parsed,
    id: `prl_${String(index).padStart(36, "0")}`,
    project_id: projectId,
    labels: parsed.labels ?? {},
    created_at: createdAt,
    updated_at: updatedAt
  });
}

function collection(links = validInputs.map(persistedLink)): ProjectResourceLinkCollectionV1 {
  return ProjectResourceLinkCollectionV1Schema.parse({
    schema: SCHEMA_IDS.projectResourceLinkCollectionV1,
    project_id: projectId,
    current_revision: updatedAt,
    links,
    link_count: links.length,
    max_items: 1_000,
    collection_digest: "a".repeat(64),
    complete: true,
    truncated: false
  });
}

describe("project resource link contracts", () => {
  test("exports and registers the exact embedded collection discriminator", () => {
    expect(SCHEMA_IDS.projectResourceLinkCollectionV1).toBe("hasna.project_resource_link_collection.v1");
    expect(ContractSchemaRegistry[SCHEMA_IDS.projectResourceLinkCollectionV1]).toBe(ProjectResourceLinkCollectionV1Schema);

    const value = collection();
    const result = validateEmbeddedContract(value);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.schemaId).toBe(SCHEMA_IDS.projectResourceLinkCollectionV1);
      expect((result.data as ProjectResourceLinkCollectionV1).link_count).toBe(validInputs.length);
    }
  });

  test("accepts every closed authority/package/target branch and normalizes portable values", () => {
    expect(ProjectResourceAuthoritySchema.options).toEqual([
      "todos",
      "conversations",
      "knowledge",
      "mementos",
      "orgs",
      "contacts"
    ]);
    expect(ProjectResourceTargetKindSchema.options).toContain("task_list");

    const parsed = validInputs.map((input) => ProjectResourceLinkInputSchema.parse(input));
    expect(parsed).toHaveLength(13);
    expect(parsed[0]?.labels?.tags).toEqual(["migration", "resource-link"]);
    expect(parsed[1]?.service_instance).toBe("https://todos.example.test/");
    expect(parsed[1]?.locator.value).toBe("8daf8a46-6993-57c0-abe6-7e01763e18af");
    expect(parsed[5]?.locator).toEqual({
      kind: "conversations_channel_id",
      value: "chn_79fa9c68937a1d020d6031dcaa3dd8d7"
    });

    expect(ProjectResourceLinkLabelsSchema.safeParse({ channel_name: "dubai", unknown: true }).success).toBe(false);
    expect(ProjectResourceLinkLocatorSchema.safeParse({ kind: "external_uuid", value: "short" }).success).toBe(false);
  });

  test("rejects wrong authority/package and authority/target combinations", () => {
    const invalid = [
      { ...validInputs[0], source_package: "@hasna/knowledge" },
      { ...validInputs[4], target_kind: "item" },
      { ...validInputs[6], source_package: "@hasna/mementos" },
      { ...validInputs[8], target_kind: "collection" },
      { ...validInputs[10], target_kind: "contact" },
      { ...validInputs[12], target_kind: "project" }
    ];

    for (const value of invalid) {
      expect(ProjectResourceLinkInputSchema.safeParse(value).success).toBe(false);
    }
  });

  test("rejects invalid branch locators and required channel presentation labels", () => {
    const invalid = [
      {
        ...validInputs[3],
        locator: { kind: "canonical_uri", value: "urn:hasna:todos:task:e2f791bd-f26b-4fac-a762-2cba96202aa5" }
      },
      {
        ...validInputs[4],
        locator: { kind: "conversations_channel_id", value: "chn_79fa9c68937a1d020d6031dcaa3dd8d7" }
      },
      {
        ...validInputs[5],
        locator: { kind: "canonical_uri", value: "urn:hasna:conversations:channel:dubai" }
      },
      {
        ...validInputs[5],
        labels: {}
      },
      {
        ...validInputs[12],
        locator: { kind: "canonical_uri", value: "urn:hasna:contacts:contact:bianca" }
      }
    ];

    for (const value of invalid) {
      expect(ProjectResourceLinkInputSchema.safeParse(value).success).toBe(false);
    }
  });

  test("rejects malformed IDs, authority-mismatched URNs, credentials, query strings, and unknown fields", () => {
    const invalid = [
      {
        ...validInputs[1],
        locator: { kind: "external_uuid", value: "8daf8a46" }
      },
      {
        ...validInputs[5],
        locator: { kind: "conversations_channel_id", value: "chn_79FA9C68937A1D020D6031DCAA3DD8D7" }
      },
      {
        ...validInputs[0],
        locator: { kind: "canonical_uri", value: "urn:hasna:knowledge:project:dubai" }
      },
      {
        ...validInputs[0],
        service_instance: "urn:hasna:knowledge:service:primary"
      },
      {
        ...validInputs[2],
        locator: { kind: "canonical_uri", value: "https://user:password@todos.example.test/plans/dubai" }
      },
      {
        ...validInputs[2],
        locator: { kind: "canonical_uri", value: "https://todos.example.test/plans/dubai?X-Amz-Signature=redacted" }
      },
      {
        ...validInputs[0],
        extra: true
      },
      {
        ...validInputs[0],
        locator: { ...validInputs[0].locator, extra: true }
      }
    ];

    for (const value of invalid) {
      expect(ProjectResourceLinkInputSchema.safeParse(value).success).toBe(false);
    }
  });

  test("enforces collection counts, ownership, completeness, and unique IDs and identities", () => {
    const links = validInputs.map(persistedLink);
    expect(collection(links).links).toHaveLength(13);

    const base = {
      schema: SCHEMA_IDS.projectResourceLinkCollectionV1,
      project_id: projectId,
      current_revision: updatedAt,
      links,
      link_count: links.length,
      max_items: 1_000,
      collection_digest: "b".repeat(64),
      complete: true,
      truncated: false
    };

    const invalid = [
      { ...base, link_count: links.length - 1 },
      { ...base, max_items: links.length - 1 },
      { ...base, complete: true, truncated: true },
      { ...base, links: [{ ...links[0]!, project_id: "wks_other" }, ...links.slice(1)] },
      { ...base, links: [...links, { ...links[0]! }], link_count: links.length + 1 },
      { ...base, links: [...links, { ...links[0]!, id: "prl_distinct" }], link_count: links.length + 1 },
      { ...base, future_field: "v2" }
    ];

    for (const value of invalid) {
      expect(ProjectResourceLinkCollectionV1Schema.safeParse(value).success).toBe(false);
    }
  });
});
