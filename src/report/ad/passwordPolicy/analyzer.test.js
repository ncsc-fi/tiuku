import issues from './issues.json';
import {
  emptyIssues
} from '../../common/analyzer';
import {
  analyzeMinLength,
  analyzeHistorySize,
  analyzeComplexityCheckEnabled,
  analyzeReversibleEncryptionEnabled,
  analyzeLockoutDuration,
  analyzeLockoutThreshold,
  analyzeLockoutResetCounterAfter
} from './analyzer';

describe('analyzeMinLength', () => {
  it('alerts if the minimum password length is less than 8', () => {
    const input = {
      value: 7
    };
    const result = analyzeMinLength(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        alerts: [issues.MIN_LENGTH_TOO_SHORT]
    }});
  });

  it('warns if the minimum password length is less than 14', () => {
    const input = {
      value: 13
    };
    const result = analyzeMinLength(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.MIN_LENGTH_TOO_SHORT],
      }});
  });

  it('considers the minimum password length OK otherwise', () => {
    const input = {
      value: 16
    };
    const result = analyzeMinLength(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});

describe('analyzeHistorySize', () => {
  it('alerts if the password history size is less than 24', () => {
    const input = {
      value: 23
    };
    const result = analyzeHistorySize(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.HISTORY_SIZE_TOO_SMALL],
      }});
  });

  it('considers the password history size OK otherwise', () => {
    const input = {
      value: 24
    };
    const result = analyzeHistorySize(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});

describe('analyzeComplexityCheckEnabled', () => {
  it('warns if the password complexity check is disabled', () => {
    const input = {
      value: false
    };
    const result = analyzeComplexityCheckEnabled(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.COMPLEXITY_CHECK_DISABLED],
      }});
  });

  it('considers the password complexity check OK if it is enabled', () => {
    const input = {
      value: true
    };
    const result = analyzeComplexityCheckEnabled(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});

describe('analyzeReversibleEncryptionEnabled', () => {
  it('alerts if reversible encryption is enabled', () => {
    const input = {
      value: true
    };
    const result = analyzeReversibleEncryptionEnabled(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        alerts: [issues.REVERSIBLE_ENCRYPTION_ENABLED]
      }
    });
  });

  it('considers reversible encryption OK if it is disabled', () => {
    const input = {
      value: false
    };
    const result = analyzeReversibleEncryptionEnabled(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});

describe('analyzeLockoutDuration', () => {
  it('warns if the duration is less than the MS-recommended value', () => {
    const input = {
      value: 14
    };
    const result = analyzeLockoutDuration(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.LOCKOUT_DURATION_TOO_SHORT]
      }
    });
  });

  it('considers the duration OK if it is greater than or equal to the MS-recommended value', () => {
    const input = {
      value: 15
    };
    const result = analyzeLockoutDuration(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});

describe('analyzeLockoutThreshold', () => {
  it('warns if the threshold is higher than the MS-recommended value', () => {
    const input = {
      value: 11
    };
    const result = analyzeLockoutThreshold(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.LOCKOUT_THRESHOLD_TOO_HIGH]
      }
    });
  });

  it('alerts if the threshold is zero (lockout disabled)', () => {
    const input = {
      value: 0
    };
    const result = analyzeLockoutThreshold(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        alerts: [issues.LOCKOUT_DISABLED]
      }
    });
  });

  it('considers the threshold OK if it is less than or equal to the MS-recommended value', () => {
    const input = {
      value: 10
    };
    const result = analyzeLockoutThreshold(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});

describe('analyzeLockoutResetCounterAfter', () => {
  it('warns if the "reset counter after" time is less than the MS-recommended value', () => {
    const input = {
      value: 14
    };
    const result = analyzeLockoutResetCounterAfter(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.LOCKOUT_RESET_COUNTER_AFTER_TOO_SHORT]
      }
    });
  });

  it('considers the "reset counter after" time OK if it is greater than or equal to the MS-recommended value', () => {
    const input = {
      value: 15
    };
    const result = analyzeLockoutResetCounterAfter(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});
