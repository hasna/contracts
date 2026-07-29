import {
  ActorRefSchema,
  SCHEMA_IDS,
  parseContract,
  type ActorRef,
} from "@hasna/contracts";

declare const actor: ActorRef;
ActorRefSchema.parse(actor);
parseContract(SCHEMA_IDS.actorRef, actor);
