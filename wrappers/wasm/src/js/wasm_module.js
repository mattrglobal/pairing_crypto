
const nodejs = process && process.versions && process.versions.node;

if (nodejs) {
    module.exports = require("./node");
}
else {
    module.exports = require("./web");
}