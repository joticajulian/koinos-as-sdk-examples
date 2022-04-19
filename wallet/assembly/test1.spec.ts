import { System } from "koinos-as-sdk";
import { main } from "./index";

jest.mock("koinos-as-sdk", () => {
  //const originalModule = jest.requireActual("koinos-as-sdk");

  return {
    //...originalModule,
    System: {
      getEntryPoint() {
        console.log("you just called getEntryPoint");
        return 2;
      },
      getContractArguments() {
        console.log("you just called getContractArguments");
        return new Uint8Array();
      },
      exitContract(n) {
        console.log(`you just called exit contract`);
        console.log(n);
      },
      setContractResult(n) {
        console.log("you just called set contract result");
        console.log(n);
      },
      getContractId() {
        console.log("you just called get contract id");
        return new Uint8Array();
      }
    },
  };
});

describe("Suite Jest", () => {
  it("should work", async () => {
    await new Promise(r => {setTimeout(r, 500);});
    System.getEntryPoint();
    main();
    expect(3).toBe(3);
  });
});