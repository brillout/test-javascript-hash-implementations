/* */ 
(function(process) {
  'use strict';
  var Buffer = require("../../../buffer@3.3.1").Buffer;
  if (process.env.OBJECT_IMPL)
    Buffer.TYPED_ARRAY_SUPPORT = false;
  var common = {};
  var assert = require("assert");
  var Buffer = require("../../../buffer@3.3.1").Buffer;
  var buff = new Buffer(Buffer.poolSize + 1);
  var slicedBuffer = buff.slice();
  assert.equal(slicedBuffer.parent, buff, 'slicedBufffer should have its parent set to the original ' + ' buffer');
})(require("process"));
