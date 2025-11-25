// sample node file
const _ = require('lodash');

function hello() {
  const obj = { a: 1 };
  const copy = _.clone(obj);
  console.log('hello', copy);
}

hello();
