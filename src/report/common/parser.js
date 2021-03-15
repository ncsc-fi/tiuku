// Common parser functions, used by all the higher-level parsers.

export class ParseError extends Error {
  name = 'ParseError';
}

// The parsing context is the path in the input document to the element being
// parsed, e.g. `.Users[3].DisplayName`. Used for error messages.
export const emptyContext = '';

const inElement = (n, context) => `${context}[${n}]`;

const inProperty = (property, context) => `${context}.${property}`;

const failParse = (context, message) => {
  if (context === emptyContext) {
    throw new ParseError(message);
  } else {
    throw new ParseError(`${context}: ${message}`);
  }
};

export const boolean = (context, x) => {
  if (typeof x === 'boolean') {
    return x;
  } else {
    failParse(context, `Expected boolean but got ${typeof x}`);
  }
};

export const string = (context, x) => {
  if (typeof x === 'string') {
    return x;
  } else {
    failParse(context, `Expected string but got ${typeof x}`);
  }
};

export const number = (context, x) => {
  if (typeof x === 'number') {
    return x;
  } else {
    failParse(context, `Expected number but got ${typeof x}`);
  }
};

export const intString = (context, x) => {
  const i = parseInt(x, 10);
  if (isNaN(i)) {
    failParse(context, 'Expected a string containing an integer');
  } else {
    return i;
  }
};

export const booleanIntString = (context, x) => {
  const i = intString(context, x);
  return i !== 0;
};

export const nonEmpty = (parser) => (context, x) => {
  const result = parser(context, x);
  if (result.length === 0) {
    failParse(context, 'Must not be empty');
  } else {
    return result;
  }
};

export const json = (context, x) => {
  const s = nonEmpty(string)(context, x);
  try {
    return JSON.parse(s);
  } catch (e) {
    failParse(context, 'Invalid JSON');
  }
};

export const array = (context, x) => {
  if (Array.isArray(x)) {
    return x;
  } else {
    failParse(context, `Expected array but got ${typeof x}`);
  }
};

export const arrayOf = (elementParser) => (context, x) => {
  const a = array(context, x);
  return a.map((x_, i) => elementParser(inElement(i, context), x_));
};

export const object = (context, x) => {
  if (x === null) {
    failParse(context, `Expected object but got null`);
  } else if (typeof x !== 'object') {
    failParse(context, `Expected object but got ${typeof x}`);
  } else {
    return x;
  }
};

export const struct = (propertyParsers) => (context, x) => {
  const o = object(context, x);
  const result = {};
  for (const property of Object.getOwnPropertyNames(propertyParsers)) {
    const propertyParser = propertyParsers[property];
    const x_ = o[property];
    result[property] = propertyParser(inProperty(property, context), x_);
  }
  return result;
};

export const objectOf = (valueParser) => (context, x) => {
  const o = object(context, x);
  const result = {};
  for (const [k, v] of Object.entries(o)) {
    result[k] = valueParser(inProperty(k, context), v);
  }
  return result;
};

export const enum_ = (...values) => (context, x) => {
  const s = nonEmpty(string)(context, x);
  if (values.includes(s)) {
    return s;
  } else {
    failParse(context, `Expected one of ${values.join('/')} but got "${s}"`);
  }
};

export const maybe = (parser) => (context, x) => {
  if (x === null) {
    return x;
  } else {
    return parser(context, x);
  }
};

export const groupObjectCounts = (context, x) => {
  const groups = arrayOf(struct({
    Name: string,
    Count: number
  }))(context, x);

  return groups.reduce((acc, g) => {
    return {
      ...acc,
      [g.Name]: g.Count
    };
  }, {});
};

export const netTimestamp = (context, x) => {
  const s = string(context, x);
  const match = s.match(/\/Date\((\d+)\)\//);
  if (match) {
    return new Date(parseInt(match[1], 10));
  } else {
    failParse(context, `Expected a .NET timestamp but got "${s}"`);
  }
};
