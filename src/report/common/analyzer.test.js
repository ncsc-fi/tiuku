import {
  propertyMapper,
  compareItems,
  emptyIssues,
  analyzer,
  arrayAnalyzer
} from './analyzer';

describe('propertyMapper', () => {
  it("returns a function that updates the input map's values with the given functions", () => {
    // Create a new property mapper function f.
    const f = propertyMapper({
      firstName: x => x.toUpperCase(),
      age: x => 1000 * x
    });

    // Pass f an input object.
    const input = {
      firstName: "John",
      lastName: "Doe",
      age: 42
    };

    const result = f(input);

    // f updates the input object's properties, leaving properties without an update function as-is.
    expect(result).toEqual({
      firstName: "JOHN",
      lastName: "Doe",
      age: 42000
    });

    // f returns an updated copy; the original input object is not modified.
    expect(input).toEqual({
      firstName: "John",
      lastName: "Doe",
      age: 42
    });
  });
});

describe('compareItems', () => {
  const alerts2Warnings0 = {
    issues: {
      warnings: [],
      alerts: ['x', 'x']
    }
  };
  const alerts2Warnings1 = {
    issues: {
      warnings: ['x'],
      alerts: ['x', 'x']
    }
  };
  const alerts1Warnings3 = {
    issues: {
      warnings: ['x', 'x', 'x'],
      alerts: ['x']
    }
  };

  it('sorts items with more alerts before items with less alerts, ignoring warnings', () => {
    expect(compareItems(alerts2Warnings0, alerts1Warnings3)).toEqual(-1);
    expect(compareItems(alerts1Warnings3, alerts2Warnings0)).toEqual(1);
  });

  it('sorts items with more warnings before items with less warnings, if they both have the same number of alerts', () => {
    expect(compareItems(alerts2Warnings1, alerts2Warnings0)).toEqual(-1);
    expect(compareItems(alerts2Warnings0, alerts2Warnings1)).toEqual(1);
  });

  it('sorts items as equal if they have the same number of warnings and alerts', () => {
    expect(compareItems(alerts2Warnings1, alerts2Warnings1)).toEqual(0);
  });
});

describe('arrayAnalyzer', () => {
  it('returns a function that analyzes each item in the given array with the given analyzer and sorts the results by issue severity', () => {
    // A dummy analyzer function.
    const f1 = analyzer(item => {
      const alerts = [];
      const warnings = [];

      // Return an alert for each foo.
      for (let i = 0; i < item.foo; i++) {
        alerts.push('some issue');
      }

      // Return a warning for each bar.
      for (let i = 0; i < item.bar; i++) {
        warnings.push('some issue');
      };

      return {alerts, warnings};
    });

    const f2 = arrayAnalyzer(f1);

    const input = [
      {
        foo: 1,
        bar: 2
      },
      {
        foo: 3,
        bar: 2
      }
    ];

    const result = f2(input);

    expect(result).toEqual([
      {
        foo: 3,
        bar: 2,
        issues: {
          ...emptyIssues,
          warnings: [
            'some issue',
            'some issue'
          ],
          alerts: [
            'some issue',
            'some issue',
            'some issue'
          ]
        }
      },
      {
        foo: 1,
        bar: 2,
        issues: {
          ...emptyIssues,
          warnings: [
            'some issue',
            'some issue'
          ],
          alerts: [
            'some issue'
          ]
        }
      }
    ]);
  });
});
