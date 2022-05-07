/*! wallet - MIT License (c) Julian Gonzalez (joticajulian@gmail.com) */

import {
  authority,
  value,
  Protobuf,
  chain,
  System,
  Crypto,
  Base58,
  Space,
  StringBytes,
} from "koinos-sdk-as";
import { wallet } from "./proto/wallet";
import { equalBytes } from "./utils";
import { VarsSpace } from "./VarsSpace";

export const GRACE_PERIOD_PROTECTION: u64 = 86400 * 1000; // 1 day
export const GRACE_PERIOD_RECOVERY: u64 = 86400 * 1000; // 1 day
export const PERIOD_UPDATE_RECOVERY: u64 = 30 * 86400 * 1000; // 30 days

const VARS_SPACE_ID = 0;
const AUTHORITIES_SPACE_ID = 1;
const PROTECTED_CONTRACTS_SPACE_ID = 2;
const REQUESTS_UPDATE_PROTECTION_SPACE_ID = 3;

function exit(message: string): void {
  System.log(message);
  System.exitContract(1);
}

function isImpossible(authority: wallet.authority): boolean {
  const keyAuths = authority.key_auths;

  // add weights from addresses
  let totalWeightAddresses: u32 = 0;
  const addresses: Array<Uint8Array> = [];
  for (let i = 0; i < keyAuths.length; i++) {
    const address = keyAuths[i].address
      ? keyAuths[i].address
      : keyAuths[i].contract_id;
    if (address == null) exit(`no address or contract_id in key_auth ${i}`);

    for (let j = 0; j < addresses.length; j++) {
      if (equalBytes(address!, addresses[j])) {
        exit("duplicate address detected");
      }
    }
    addresses.push(address!);

    if (keyAuths[i].address != null) {
      totalWeightAddresses += keyAuths[i].weight;
    }
  }

  let hasContract = false;
  for (let i = 0; i < keyAuths.length; i++) {
    if (keyAuths[i].contract_id != null) {
      hasContract = true;
      if (
        totalWeightAddresses + keyAuths[i].weight <
        authority.weight_threshold
      ) {
        System.log(
          `impossible for contract ${Base58.encode(keyAuths[i].contract_id!)}`
        );
        return true;
      }
    }
  }

  if (hasContract) return false;
  return totalWeightAddresses < authority.weight_threshold;
}

class ResultVerifyArgumentsAuthority {
  existOwner: boolean;
  existingAuthority: wallet.authority | null;
  constructor(existOwner: boolean, existingAuthority: wallet.authority | null) {
    this.existOwner = existOwner;
    this.existingAuthority = existingAuthority;
  }
}

class ResultVerifyArgumentsProtection {
  protectionKey: Uint8Array;
  existingAuthority: wallet.authority_contract | null;
  constructor(
    protectionKey: Uint8Array,
    existingAuthority: wallet.authority_contract | null
  ) {
    this.protectionKey = protectionKey;
    this.existingAuthority = existingAuthority;
  }
}

export class Result {
  error: boolean;
  message: string;
  constructor(error: boolean, message: string) {
    this.error = error;
    this.message = message;
  }
}

export class Wallet {
  contractId: Uint8Array;
  varsSpace: VarsSpace;
  authorities: Space.Space<string, wallet.authority>;
  protections: Space.Space<Uint8Array, wallet.authority_contract>;
  requests: Space.Space<Uint8Array, wallet.request_update_protection_arguments>;

  constructor() {
    this.contractId = System.getContractId();
    this.varsSpace = new VarsSpace(this.contractId, VARS_SPACE_ID);
    this.authorities = new Space.Space(
      this.contractId,
      AUTHORITIES_SPACE_ID,
      wallet.authority.decode,
      wallet.authority.encode
    );
    this.protections = new Space.Space(
      this.contractId,
      PROTECTED_CONTRACTS_SPACE_ID,
      wallet.authority_contract.decode,
      wallet.authority_contract.encode
    );
    this.requests = new Space.Space(
      this.contractId,
      REQUESTS_UPDATE_PROTECTION_SPACE_ID,
      wallet.request_update_protection_arguments.decode,
      wallet.request_update_protection_arguments.encode
    );
  }

  _getProtectionByTarget(
    call: authority.call_target,
    remainingEntryPoints: bool
  ): wallet.authority_contract | null {
    const protectedContract = new wallet.protected_contract(
      call.contract_id,
      remainingEntryPoints ? 0 : call.entry_point,
      remainingEntryPoints
    );
    const key = Protobuf.encode(
      protectedContract,
      wallet.protected_contract.encode
    );
    return this.protections.get(key);
  }

  _requireAuthority(name: string): void {
    const result = this._verifyAuthority(name);
    if (result.error) exit(result.message);
  }

  _verifyAuthority(name: string): Result {
    const auth = this.authorities.get(name);
    if (auth == null) {
      return new Result(true, `invalid authority '${name}'`);
    }

    const sigBytes =
      System.getTransactionField("signatures")!.message_value!.value!;
    const signatures = Protobuf.decode<value.list_type>(
      sigBytes,
      value.list_type.decode
    );
    const txId = System.getTransactionField("id")!.bytes_value!;

    let totalWeight: u32 = 0;

    // add weights from signatures
    const signers: Array<Uint8Array | null> = [];
    for (let i = 0; i < signatures.values.length; i++) {
      const publicKey = System.recoverPublicKey(
        signatures.values[i].bytes_value!,
        txId
      );
      const address = Crypto.addressFromPublicKey(publicKey!);
      for (let j = 0; j < signers.length; j++) {
        if (equalBytes(address, signers[j]!)) {
          return new Result(true, "duplicate signature detected");
        }
      }

      signers.push(address);

      for (let j = 0; j < auth.key_auths.length; j++) {
        const keyAddress = auth.key_auths[j].address;
        if (keyAddress != null && equalBytes(address, keyAddress)) {
          totalWeight += auth.key_auths[j].weight;
        }
      }
    }

    // add weight from the caller
    const caller = System.getCaller().caller;
    if (caller != null) {
      for (let j = 0; j < auth.key_auths.length; j++) {
        const contractId = auth.key_auths[j].contract_id;
        if (contractId != null && equalBytes(caller, contractId)) {
          totalWeight += auth.key_auths[j].weight;
        }
      }
    }

    if (totalWeight < auth.weight_threshold) {
      return new Result(true, `authority ${name} failed`);
    }

    return new Result(false, "");
  }

  verifyArgumentsAuthority(
    name: string | null,
    authority: wallet.authority | null,
    argImpossible: bool,
    isNewAuthority: boolean,
    remove: bool
  ): ResultVerifyArgumentsAuthority {
    const existOwner = this.authorities.has("owner");
    if (isNewAuthority && !existOwner && name != "owner") {
      exit("the first authority must be 'owner'");
    }

    if (name == null) {
      exit("name undefined");
    }

    if (remove && name == "owner") exit("owner authority can not be removed");

    if (!remove && authority == null) {
      exit("authority undefined");
    }

    const existingAuthority = this.authorities.get(name!);
    if (isNewAuthority && existingAuthority) {
      exit(`authority ${name!} already exists`);
    }
    if (!isNewAuthority && !existingAuthority) {
      exit(`authority ${name!} does not exist`);
    }

    if (!remove) {
      const impossible = isImpossible(authority!);
      if (impossible && (name == "owner" || name == "recovery")) {
        exit(`${name!} authority can not be impossible`);
      }
      if (impossible != argImpossible) {
        if (impossible)
          exit(
            "impossible authority: If this is your intention tag it as impossible"
          );
        else exit("the authority was tagged as impossible but it is not");
      }
    }
    return new ResultVerifyArgumentsAuthority(existOwner, existingAuthority);
  }

  add_authority(
    args: wallet.add_authority_arguments
  ): wallet.add_authority_result {
    const resultVerify = this.verifyArgumentsAuthority(
      args.name,
      args.authority,
      args.impossible,
      true,
      false
    );
    if (resultVerify.existOwner) this._requireAuthority("owner");
    args.authority!.last_update = System.getHeadInfo().head_block_time;
    this.authorities.put(args.name!, args.authority!);
    return new wallet.add_authority_result(true);
  }

  request_update_recovery(
    args: wallet.request_update_recovery_arguments
  ): wallet.request_update_recovery_result {
    this.verifyArgumentsAuthority(
      "recovery",
      args.authority,
      false,
      false,
      args.remove
    );
    const existingRequest = this.varsSpace.getRequestUpdateRecovery();
    if (existingRequest) exit("request ongoing to update recovery");
    if (!args.remove) args.authority!.last_update = 0;
    args.application_time =
      System.getHeadInfo().head_block_time + PERIOD_UPDATE_RECOVERY;
    this._requireAuthority("owner");

    this.varsSpace.putRequestUpdateRecovery(args);
    return new wallet.request_update_recovery_result(true);
  }

  cancel_request_update_recovery(
    args: wallet.cancel_request_update_recovery_arguments
  ): wallet.cancel_request_update_recovery_result {
    this._requireAuthority("owner");
    const request = this.varsSpace.getRequestUpdateRecovery();
    if (!request) exit("request update recovery not found");
    this.varsSpace.removeRequestUpdateRecovery();
    return new wallet.cancel_request_update_recovery_result(true);
  }

  update_authority(
    args: wallet.update_authority_arguments
  ): wallet.update_authority_result {
    const resultVerify = this.verifyArgumentsAuthority(
      args.name,
      args.authority,
      args.impossible,
      false,
      args.remove
    );
    let authorized: boolean = false;
    let verifAuthority = this._verifyAuthority("recovery");
    if (verifAuthority.error) {
      System.log(verifAuthority.message);
      if (args.name == "recovery") {
        const now = System.getHeadInfo().head_block_time;
        if (
          resultVerify.existingAuthority!.last_update + GRACE_PERIOD_RECOVERY >
          now
        ) {
          verifAuthority = this._verifyAuthority("owner");
          if (verifAuthority.error) {
            System.log(verifAuthority.message);
          } else {
            authorized = true;
          }
        } else {
          System.log("not in grace period");
        }

        if (!authorized) {
          const request = this.varsSpace.getRequestUpdateRecovery();
          if (!request) {
            exit("request to update recovery not found");
          }
          if (request!.application_time > now) {
            exit("it is not yet the application time");
          }
          const bytes1 = args.remove
            ? new Uint8Array(0)
            : Protobuf.encode(args.authority, wallet.authority.encode);
          const bytes1Req = args.remove
            ? new Uint8Array(0)
            : Protobuf.encode(request!.authority, wallet.authority.encode);
          if (!equalBytes(bytes1, bytes1Req)) {
            exit("arguments does not match with the request");
          }
          authorized = true;
        }
      } else {
        verifAuthority = this._verifyAuthority("owner");
        if (verifAuthority.error) {
          System.log(verifAuthority.message);
        } else {
          authorized = true;
        }
      }
    } else {
      authorized = true;
    }

    if (!authorized) System.exitContract(1);

    // update authority
    if (args.remove) {
      this.authorities.remove(args.name!);
    } else {
      args.authority!.last_update = System.getHeadInfo().head_block_time;
      this.authorities.put(args.name!, args.authority!);
    }

    // remove existing request
    if (args.name == "recovery") {
      const request = this.varsSpace.getRequestUpdateRecovery();
      if (request) this.varsSpace.removeRequestUpdateRecovery();
    }

    return new wallet.update_authority_result(true);
  }

  verifyArgumentsProtection(
    protected_contract: wallet.protected_contract | null,
    authority: wallet.authority_contract | null,
    isNewProtection: boolean,
    remove: bool
  ): ResultVerifyArgumentsProtection {
    if (protected_contract == null) {
      exit("protected undefined");
    }
    if (!remove && authority == null) {
      exit("authority undefined");
    }
    if (protected_contract!.contract_id == null) {
      exit("protected_contract.contract_id not defined");
    }
    const protectionKey = Protobuf.encode(
      protected_contract!,
      wallet.protected_contract.encode
    );
    const existingAuthority = this.protections.get(protectionKey);
    if (isNewProtection && existingAuthority) {
      exit("protected contract already exists");
    }
    if (!isNewProtection && !existingAuthority) {
      exit("protected contract does not exist");
    }

    if (!remove) {
      if (authority!.native != null) {
        const auth = this.authorities.get(authority!.native!);
        if (auth == null) {
          exit(`authority '${authority!.native!}' does not exist`);
        }
      } else if (authority!.external != null) {
        if (authority!.external!.contract_id == null)
          exit("authority.external.contract_id not defined");
      } else {
        exit("authority without native or external");
      }
    }
    return new ResultVerifyArgumentsProtection(
      protectionKey,
      existingAuthority
    );
  }

  add_protection(
    args: wallet.add_protection_arguments
  ): wallet.add_protection_result {
    const resultVerify = this.verifyArgumentsProtection(
      args.protected_contract,
      args.authority,
      true,
      false
    );

    args.authority!.last_update = System.getHeadInfo().head_block_time;
    this._requireAuthority("owner");
    this.protections.put(resultVerify.protectionKey, args.authority!);

    return new wallet.add_protection_result(true);
  }

  request_update_protection(
    args: wallet.request_update_protection_arguments
  ): wallet.request_update_protection_result {
    const resultVerify = this.verifyArgumentsProtection(
      args.protected_contract,
      args.authority,
      false,
      args.remove
    );

    const requests = this.requests.getMany(new Uint8Array(1));
    for (let i = 0; i < requests.length; i++) {
      const pKey = Protobuf.encode(
        requests[i].value.protected_contract,
        wallet.protected_contract.encode
      );
      if (equalBytes(resultVerify.protectionKey, pKey))
        exit(`request ongoing for this protected contract`);
    }

    if (!args.remove) args.authority!.last_update = 0;
    args.application_time =
      System.getHeadInfo().head_block_time +
      resultVerify.existingAuthority!.delay_update;
    const counter = this.varsSpace.getRequestsCounter() + 1;
    args.id = counter;
    this._requireAuthority("owner");

    const key = VarsSpace.calcCounterKey(args.id);
    this.requests.put(key, args);
    this.varsSpace.putRequestsCounter(counter);

    return new wallet.request_update_protection_result(true);
  }

  cancel_request_update_protection(
    args: wallet.cancel_request_update_protection_arguments
  ): wallet.cancel_request_update_protection_result {
    this._requireAuthority("owner");
    const key = VarsSpace.calcCounterKey(args.id);
    const request = this.requests.get(key);
    if (!request) exit("request not found");
    this.requests.remove(key);
    return new wallet.cancel_request_update_protection_result(true);
  }

  update_protection(
    args: wallet.update_protection_arguments
  ): wallet.update_protection_result {
    const resultVerify = this.verifyArgumentsProtection(
      args.protected_contract,
      args.authority,
      false,
      args.remove
    );

    let authorized: boolean = false;
    let indexRequest: i32 = -1;
    let requests: System.ProtoDatabaseObject<wallet.request_update_protection_arguments>[] =
      [];
    const bytes1 = Protobuf.encode(
      args.protected_contract,
      wallet.protected_contract.encode
    );
    const bytes2 = args.remove
      ? new Uint8Array(0)
      : Protobuf.encode(args.authority, wallet.authority_contract.encode);

    let verifAuthority = this._verifyAuthority("recovery");
    if (verifAuthority.error) {
      System.log(verifAuthority.message);
      const now = System.getHeadInfo().head_block_time;
      if (
        resultVerify.existingAuthority!.last_update + GRACE_PERIOD_PROTECTION >
        now
      ) {
        verifAuthority = this._verifyAuthority("owner");
        if (verifAuthority.error) {
          System.log(verifAuthority.message);
        } else {
          authorized = true;
        }
      } else {
        System.log("not in grace period");
      }

      if (!authorized) {
        requests = this.requests.getMany(new Uint8Array(1));
        for (let i = 0; i < requests.length; i++) {
          const bytes1Req = Protobuf.encode(
            requests[i].value.protected_contract,
            wallet.protected_contract.encode
          );
          const bytes2Req = args.remove
            ? new Uint8Array(0)
            : Protobuf.encode(
                requests[i].value.authority,
                wallet.authority_contract.encode
              );
          if (equalBytes(bytes1, bytes1Req) && equalBytes(bytes2, bytes2Req)) {
            indexRequest = i;
            break;
          }
        }
        if (indexRequest < 0) {
          exit("request to update protection not found");
        }
        if (requests[indexRequest].value.application_time > now) {
          exit("it is not yet the application time");
        }
        authorized = true;
      }
    } else {
      authorized = true;
    }

    if (!authorized) System.exitContract(1);

    // update protection
    if (args.remove) {
      this.protections.remove(resultVerify.protectionKey);
    } else {
      args.authority!.last_update = System.getHeadInfo().head_block_time;
      this.protections.put(resultVerify.protectionKey, args.authority!);
    }

    // remove existing request
    if (indexRequest < 0) {
      requests = this.requests.getMany(new Uint8Array(1));
      for (let i = 0; i < requests.length; i++) {
        const bytes1Req = Protobuf.encode(
          requests[i].value.protected_contract,
          wallet.protected_contract.encode
        );
        const bytes2Req = args.remove
          ? new Uint8Array(0)
          : Protobuf.encode(
              requests[i].value.authority,
              wallet.authority_contract.encode
            );
        if (equalBytes(bytes1, bytes1Req) && equalBytes(bytes2, bytes2Req)) {
          indexRequest = i;
          break;
        }
      }
    }
    if (indexRequest >= 0) {
      const key = VarsSpace.calcCounterKey(requests[indexRequest].value.id);
      this.requests.remove(key);
    }

    return new wallet.update_protection_result(true);
  }

  get_authorities(
    args: wallet.get_authorities_arguments
  ): wallet.get_authorities_result {
    const result = new wallet.get_authorities_result();
    const dbAuthorities = this.authorities.getMany("");
    for (let i = 0; i < dbAuthorities.length; i++) {
      result.authorities.push(
        new wallet.add_authority_arguments(
          StringBytes.bytesToString(dbAuthorities[i].key),
          dbAuthorities[i].value
        )
      );
    }
    return result;
  }

  get_protections(
    args: wallet.get_protections_arguments
  ): wallet.get_protections_result {
    const result = new wallet.get_protections_result();
    const protections = this.protections.getMany(new Uint8Array(1));
    for (let i = 0; i < protections.length; i++) {
      const protectedContract = Protobuf.decode<wallet.protected_contract>(
        protections[i].key!,
        wallet.protected_contract.decode
      );
      const authorityContract = protections[i].value;
      result.protections.push(
        new wallet.add_protection_arguments(
          protectedContract,
          authorityContract
        )
      );
    }
    return result;
  }

  get_request_update_recovery(
    args: wallet.get_request_update_recovery_arguments
  ): wallet.get_request_update_recovery_result {
    const request = this.varsSpace.getRequestUpdateRecovery();
    const result = new wallet.get_request_update_recovery_result(request);
    return result;
  }

  get_requests_update_protection(
    args: wallet.get_requests_update_protection_arguments
  ): wallet.get_requests_update_protection_result {
    const result = new wallet.get_requests_update_protection_result();
    const requests = this.requests.getMany(new Uint8Array(1));
    for (let i = 0; i < requests.length; i++) {
      const request = requests[i].value;
      if (request == null) {
        System.log(`The key ${i} is empty`);
      } else {
        result.requests.push(request);
      }
    }
    return result;
  }

  authorize(args: authority.authorize_arguments): authority.authorize_result {
    if (args.type == authority.authorization_type.contract_call) {
      // check if there is an authority for the specific endpoint
      let authContract = this._getProtectionByTarget(args.call!, false);
      if (!authContract) {
        // check if there is an authority for the remaining entry points
        authContract = this._getProtectionByTarget(args.call!, true);
        if (!authContract) {
          this._requireAuthority("owner"); // todo: change to "active" ?
          return new authority.authorize_result(true);
        }
      }

      if (authContract.native != null) {
        this._requireAuthority(authContract.native!);
        return new authority.authorize_result(true);
      }

      if (authContract.external != null) {
        const contractId = authContract.external!.contract_id!;
        const entryPoint = authContract.external!.entry_point;
        const resBuf = System.callContract(
          contractId,
          entryPoint,
          Protobuf.encode(args, authority.authorize_arguments.encode)
        )!;
        const authorized = Protobuf.decode<authority.authorize_result>(
          resBuf,
          authority.authorize_result.decode
        );
        return authorized;
      }

      exit("Authority is not defined correctly");
    }
    // todo: type upload_contract
    // todo: type transaction_application
    return new authority.authorize_result(false);
  }

  require_authority(
    args: wallet.require_authority_arguments
  ): wallet.require_authority_result {
    this._requireAuthority(args.name!);
    return new wallet.require_authority_result(true);
  }

  // todo: authorize update authority protected contract
  // todo: create events
}
