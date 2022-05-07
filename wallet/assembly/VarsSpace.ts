import { Reader, Writer } from "as-proto";
import { chain, System, value as val, Protobuf } from "koinos-sdk-as";
import { wallet } from "./proto/wallet";
import { equalBytes } from "./utils";

const PROTECTED_KEYS_KEY = new Uint8Array(1);
const REQUEST_UPDATE_RECOVERY_KEY = new Uint8Array(1);
const REQUESTS_UPDATE_PROTECTION_KEYS_KEY = new Uint8Array(1);
const COUNTER_REQUESTS_UPDATE_PROTECTION_KEY = new Uint8Array(1);
PROTECTED_KEYS_KEY[0] = 1;
REQUEST_UPDATE_RECOVERY_KEY[0] = 2;
REQUESTS_UPDATE_PROTECTION_KEYS_KEY[0] = 3;
COUNTER_REQUESTS_UPDATE_PROTECTION_KEY[0] = 4;

export class VarsSpace {
  space: chain.object_space;

  constructor(contractId: Uint8Array, spaceId: u32) {
    this.space = new chain.object_space(false, contractId, spaceId);
  }

  // Request Update Recovery

  getRequestUpdateRecovery(): wallet.request_update_recovery_arguments | null {
    return System.getObject<
      Uint8Array,
      wallet.request_update_recovery_arguments
    >(
      this.space,
      REQUEST_UPDATE_RECOVERY_KEY,
      wallet.request_update_recovery_arguments.decode
    );
  }

  putRequestUpdateRecovery(
    args: wallet.request_update_recovery_arguments
  ): void {
    System.putObject(
      this.space,
      REQUEST_UPDATE_RECOVERY_KEY,
      args,
      wallet.request_update_recovery_arguments.encode
    );
  }

  removeRequestUpdateRecovery(): void {
    System.removeObject(this.space, REQUEST_UPDATE_RECOVERY_KEY);
  }

  // Counter Request Protections

  getRequestsCounter(): u32 {
    const counter = System.getObject<Uint8Array, val.value_type>(
      this.space,
      COUNTER_REQUESTS_UPDATE_PROTECTION_KEY,
      val.value_type.decode
    );
    return counter ? counter.uint32_value : 0;
  }

  putRequestsCounter(n: u32): void {
    const counter = new val.value_type(null, 0, 0, 0, 0, n);
    System.putObject(
      this.space,
      COUNTER_REQUESTS_UPDATE_PROTECTION_KEY,
      counter,
      val.value_type.encode
    );
  }

  static calcCounterKey(n: u32): Uint8Array {
    const value = new val.value_type(null, 0, 0, 0, 0, n);
    return Protobuf.encode(value, val.value_type.encode);
  }
}
