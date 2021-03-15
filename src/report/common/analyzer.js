export const propertyMapper = updateFunctions => inputObject => {
  const resultObject = {...inputObject};
  for (const property of Object.getOwnPropertyNames(updateFunctions)) {
    const updateFunction = updateFunctions[property];
    const inputValue = inputObject[property];
    resultObject[property] = updateFunction(inputValue);
  }
  return resultObject;
};

export const compareItems = (a, b) => {
  if (a.issues.alerts.length > b.issues.alerts.length) {
    return -1;
  } else if (a.issues.alerts.length < b.issues.alerts.length) {
    return 1;
  } else if (a.issues.warnings.length > b.issues.warnings.length) {
    return -1;
  } else if (a.issues.warnings.length < b.issues.warnings.length) {
    return 1;
  } else {
    return 0;
  }
};

export const emptyIssues = {
  suggestions: [],
  warnings: [],
  alerts: []
};

export const analyzer = f => input => {
  return {
    ...input,
    issues: {
      ...emptyIssues,
      ...f(input)
    }
  };
};

export const arrayAnalyzer = f => input => input.map(f).sort(compareItems);
