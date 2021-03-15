import issues from './issues.json';
import {
  analyzer,
  propertyMapper
} from '../../common/analyzer';

export const analyzeMinLength = analyzer(({value}) => {
  if (value < 8) {
    return {
      alerts: [issues.MIN_LENGTH_TOO_SHORT]
    };
  } else if (value < 14) {
    return {
      warnings: [issues.MIN_LENGTH_TOO_SHORT]
    };
  }
});

export const analyzeHistorySize = analyzer(({value}) => {
  if (value < 24) {
    return {
      warnings: [issues.HISTORY_SIZE_TOO_SMALL]
    };
  }
});

export const analyzeComplexityCheckEnabled = analyzer(({value}) => {
  if (!value) {
    return {
      warnings: [issues.COMPLEXITY_CHECK_DISABLED]
    };
  }
});

export const analyzeReversibleEncryptionEnabled = analyzer(({value}) => {
  if (value) {
    return {
      alerts: [issues.REVERSIBLE_ENCRYPTION_ENABLED]
    };
  }
});

export const analyzeLockoutDuration = analyzer(({value}) => {
  if (value < 15) {
    return {
      warnings: [issues.LOCKOUT_DURATION_TOO_SHORT]
    };
  }
});

export const analyzeLockoutThreshold = analyzer(({value}) => {
  if (value === 0) {
    return {
      alerts: [issues.LOCKOUT_DISABLED]
    };
  } else if (value > 10) {
    return {
      warnings: [issues.LOCKOUT_THRESHOLD_TOO_HIGH]
    };
  }
});

export const analyzeLockoutResetCounterAfter = analyzer(({value}) => {
  if (value < 15) {
    return {
      warnings: [issues.LOCKOUT_RESET_COUNTER_AFTER_TOO_SHORT]
    };
  }
});

const analyze = propertyMapper({
  minLength: analyzeMinLength,
  historySize: analyzeHistorySize,
  complexityCheckEnabled: analyzeComplexityCheckEnabled,
  reversibleEncryptionEnabled: analyzeReversibleEncryptionEnabled,
  lockout: propertyMapper({
    duration: analyzeLockoutDuration,
    threshold: analyzeLockoutThreshold,
    resetCounterAfter: analyzeLockoutResetCounterAfter
  })
});

export default analyze;
