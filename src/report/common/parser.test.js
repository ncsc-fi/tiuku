import {
  boolean,
  string,
  number,
  intString,
  booleanIntString,
  nonEmpty,
  json,
  array,
  arrayOf,
  object,
  struct,
  objectOf,
  enum_,
  maybe,
  groupObjectCounts,
  netTimestamp
} from './parser';

describe('boolean', () => {
  it('throws an exception if the input is not a boolean', () => {
    const context = 'some.context';
    const input = [];
    expect(() => {
      boolean(context, input);
    }).toThrow('some.context: Expected boolean but got object');
  });

  it('returns the input if it is a boolean', () => {
    const context = 'some.context';
    const input = true;
    const result = boolean(context, input);
    expect(result).toEqual(input);
  });
});

describe('string', () => {
  it('throws an exception if the input is not a string', () => {
    const context = 'some.context';
    const input = [];
    expect(() => {
      string(context, input);
    }).toThrow('some.context: Expected string but got object');
  });

  it('returns the input if it is a string', () => {
    const context = 'some.context';
    const input = 'some string';
    const result = string(context, input);
    expect(result).toEqual(input);
  });
});

describe('number', () => {
  it('throws an exception if the input is not a number', () => {
    const context = 'some.context';
    const input = [];
    expect(() => {
      number(context, input);
    }).toThrow('some.context: Expected number but got object');
  });

  it('returns the input if it is a number', () => {
    const context = 'some.context';
    const input = 123.456;
    const result = number(context, input);
    expect(result).toEqual(input);
  });
});

describe('intString', () => {
  it('throws an exception if the input is not a string containing a number', () => {
    const context = 'some.context';
    const input = 'this is not an integer';
    expect(() => {
      intString(context, input);
    }).toThrow('some.context: Expected a string containing an integer');
  });

  it('returns the parsed number if the input is a string containing a number', () => {
    const context = 'some.context';
    const input = '123';
    const result = intString(context, input);
    expect(result).toEqual(123);
  });
});

describe('booleanIntString', () => {
  it('returns false if the input is a string containing the number 0', () => {
    const context = 'some.context';
    const input = '0';
    const result = booleanIntString(context, input);
    expect(result).toEqual(false);
  });

  it('returns true if the input is a string containing any other number', () => {
    const context = 'some.context';
    const input = '123';
    const result = booleanIntString(context, input);
    expect(result).toEqual(true);
  });
});

describe('nonEmpty', () => {
  it('throws an exception if the parsed input has length of 0', () => {
    const context = 'some.context';
    const input = '';
    expect(() => {
      nonEmpty(string)(context, input);
    }).toThrow('some.context: Must not be empty');
  });

  it('returns the parsed input if its length is non-zero', () => {
    const context = 'some.context';
    const input = 'some string';
    const result = nonEmpty(string)(context, input);
    expect(result).toEqual(input);
  });
});

describe('json', () => {
  it('throws an exception if the input is invalid JSON', () => {
    const context = 'some.context';
    const input = 'in{valid';
    expect(() => {
      json(context, input);
    }).toThrow('some.context: Invalid JSON');
  });

  it('returns the parsed data structure if the input is valid JSON', () => {
    const context = 'some.context';
    const input = '{"foo": [1, 2, 3]}';
    const result = json(context, input);
    expect(result).toEqual({foo: [1, 2, 3]});
  });
});

describe('array', () => {
  it('throws an exception if the input is not an array', () => {
    const context = 'some.context';
    const input = {};
    expect(() => {
      array(context, input);
    }).toThrow('some.context: Expected array but got object');
  });

  it('returns the input if it is an array', () => {
    const context = 'some.context';
    const input = [1, 2, 3];
    const result = array(context, input);
    expect(result).toEqual(input);
  });
});

describe('arrayOf', () => {
  it('throws an exception if some element of the input does not have the expected structure', () => {
    const context = 'some.context';
    const input = ['{}', '123', 'in{valid', '["a", "b", "c"]'];
    expect(() => {
      arrayOf(json)(context, input);
    }).toThrow('some.context[2]: Invalid JSON');
  });

  it('returns the array with each element parsed if the elements have the expected structure', () => {
    const context = 'some.context';
    const input = ['{}', '123', '["a", "b", "c"]'];
    const result = arrayOf(json)(context, input);
    expect(result).toEqual([{}, 123, ['a', 'b', 'c']]);
  });
});

describe('object', () => {
  it('throws an exception if the input is not an object', () => {
    const context = 'some.context';
    const input = 123;
    expect(() => {
      object(context, input);
    }).toThrow('some.context: Expected object but got number');
  });

  it('throws an exception if the input is null', () => {
    const context = 'some.context';
    const input = null;
    expect(() => {
      object(context, input);
    }).toThrow('some.context: Expected object but got null');
  });

  it('returns the input if it is an object', () => {
    const context = 'some.context';
    const input = {foo: 1};
    const result = object(context, input);
    expect(result).toEqual(input);
  });
});

describe('struct', () => {
  it('throws an exception if some property of the object does not have the expected structure', () => {
    const context = 'some.context';
    const input = {
      foo: '{"some": "json"}',
      bar: ['a', 'b', 123, 'd'],
      baz: 'extra key'
    };
    expect(() => {
      struct({
        foo: json,
        bar: arrayOf(string)
      })(context, input);
    }).toThrow('some.context.bar[2]: Expected string but got number');
  });

  it('returns the object with each property parsed if the properties have the expected structure', () => {
    const context = 'some.context';
    const input = {
      foo: '{"some": "json"}',
      bar: ['a', 'b', 'c', 'd'],
      baz: 'extra key'
    };
    const result = struct({
      foo: json,
      bar: arrayOf(string)
    })(context, input);
    // No extra keys
    expect(result).toEqual({
      foo: {some: 'json'},
      bar: ['a', 'b', 'c', 'd']
    });
  });
});

describe('objectOf', () => {
  it('throws an exception if a property has a value that does not have the expected structure', () => {
    const context = 'some.context';
    const input = {
      foo: 123,
      bar: 456,
      baz: {this: 'is wrong'}
    };
    expect(() => {
      objectOf(number)(context, input);
    }).toThrow('some.context.baz: Expected number but got object');
  });

  it('returns the object with each property parsed if the properties have the expected structure', () => {
    const context = 'some.context';
    const input = {
      foo: '123',
      bar: '["baz"]'
    };
    const result = objectOf(json)(context, input);
    expect(result).toEqual({
      foo: 123,
      bar: ['baz']
    });
  });
});

describe('enum', () => {
  it('throws an exception if the input is not one of the expected values', () => {
    const context = 'some.context';
    const input = 'LOL';
    expect(() => {
      enum_('FOO', 'BAR', 'BAZ')(context, input);
    }).toThrow('some.context: Expected one of FOO/BAR/BAZ but got "LOL"');
  });

  it('returns the input if it is one of the expected values', () => {
    const context = 'some.context';
    const input = 'BAR';
    const result = enum_('FOO', 'BAR', 'BAZ')(context, input);
    expect(result).toEqual(input);
  });
});

describe('maybe', () => {
  it('returns the input if it is null', () => {
    const context = 'some.context';
    const input = null;
    const result = maybe(json)(context, input);
    expect(result).toEqual(input);
  });

  it('returns the input parsed if it is not null', () => {
    const context = 'some.context';
    const input = '{"foo": 123}';
    const result = maybe(json)(context, input);
    expect(result).toEqual({foo: 123});
  });
});

describe('groupObjectCounts', () => {
  it("parses the object counts as returned by the Powershell Group-Object cmdlet", () => {
    const context = 'some.context';
    const input = [
      {
        Values: [
          'Windows Server 2019 Datacenter'
        ],
        Count: 1,
        Group: [],
        Name: 'Windows Server 2019 Datacenter'
      },
      {
        Values: [
          'Windows 10 Pro N'
        ],
        Count: 2,
        Group: [],
        Name: 'Windows 10 Pro N'
      }
    ];
    const result = groupObjectCounts(context, input);
    expect(result).toEqual({
      'Windows Server 2019 Datacenter': 1,
      'Windows 10 Pro N': 2
    });
  });
});

describe('netTimestamp', () => {
  it('throws an exception if the input format is incorrect', () => {
    const context = 'some.context';
    const input = '1608198300000';
    expect(() => {
      netTimestamp(context, input);
    }).toThrow('some.context: Expected a .NET timestamp but got "1608198300000"');
  });

  it('parses a .NET timestamp into a JS Date', () => {
    const context = 'some.context';
    const input = '/Date(1608198300526)/';
    const result = netTimestamp(context, input);
    expect(result).toEqual(new Date(Date.parse('2020-12-17T09:45:00.526Z')));
  });
});
