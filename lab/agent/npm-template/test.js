const assert = require("assert");
const _ = require("lodash");

assert.deepStrictEqual(_.chunk([1, 2, 3], 2), [[1, 2], [3]]);
assert.strictEqual(_.uniq([1, 1, 2]).length, 2);
console.log("all tests passed");
