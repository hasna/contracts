import {
  BlobRefSchema,
  CapabilityDescriptorSchema,
  CORE_SCHEMA_IDS,
  ErrorSchema,
  EventEnvelopeSchema,
  IdempotencySchema,
  PrincipalSchema,
  SecretRefSchema,
  TenantContextSchema,
  parseCoreContract,
  type CapabilityDescriptor,
  type ContractError,
  type EventEnvelope,
} from "@hasna/contracts";
import bundle from "@hasna/contracts/json-schemas/bundle.json";

void [
  BlobRefSchema,
  CapabilityDescriptorSchema,
  ErrorSchema,
  EventEnvelopeSchema,
  IdempotencySchema,
  PrincipalSchema,
  SecretRefSchema,
  TenantContextSchema,
  bundle,
];

declare const error: ContractError;
declare const event: EventEnvelope;
declare const capability: CapabilityDescriptor;
parseCoreContract(CORE_SCHEMA_IDS.error, error);
parseCoreContract(CORE_SCHEMA_IDS.eventEnvelope, event);
parseCoreContract(CORE_SCHEMA_IDS.capabilityDescriptor, capability);
