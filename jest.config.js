module.exports = {
    preset: "ts-jest",
    testEnvironment: "node",
    testTimeout: 120000,
    rootDir: ".",
    roots: ["<rootDir>/wallet/"],
    testMatch: ["**/?(*.|*-)+(spec|test).ts"],
    transform: {
      "^.+\\.(t|j)s$": "ts-jest",
    },
    esModuleInterop: true,
    transformIgnorePatterns: ["/node_modules/"],
    moduleFileExtensions: ["js", "json", "ts"],
    coverageDirectory: "./coverage/",
    collectCoverageFrom: [],
    coverageReporters: ["text", "lcov", "json", "clover", "cobertura"],
  };