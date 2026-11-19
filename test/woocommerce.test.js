"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isWooProductId } = require("../src/woocommerce");

test("WooCommerce product IDs accept numeric IDs only", () => {
  assert.equal(isWooProductId("123"), true);
  assert.equal(isWooProductId(123), true);
  assert.equal(isWooProductId("local:123"), false);
  assert.equal(isWooProductId(""), false);
  assert.equal(isWooProductId("12x"), false);
});
