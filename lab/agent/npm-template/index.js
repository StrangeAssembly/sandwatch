const _ = require("lodash");
const chalk = require("chalk");

const items = ["write code", "run tests", "review diff", "ship"];
const chunks = _.chunk(items, 2);
console.log(chalk.green("todo chunks:"), JSON.stringify(chunks));
