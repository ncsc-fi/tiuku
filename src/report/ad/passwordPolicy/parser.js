import {
  boolean,
  number,
  struct
} from '../../common/parser';

const passwordPolicy = (context, x) => {
  const o = struct({
    MinPasswordLength: number,
    PasswordHistoryCount: number,
    ComplexityEnabled: boolean,
    ReversibleEncryptionEnabled: boolean,
    LockoutThreshold: number,
    LockoutDuration: struct({
      TotalMinutes: number
    }),
    LockoutObservationWindow: struct({
      TotalMinutes: number
    })
  })(context, x);

  return {
    minLength: {
      value: o.MinPasswordLength
    },
    historySize: {
      value: o.PasswordHistoryCount
    },
    complexityCheckEnabled: {
      value: o.ComplexityEnabled
    },
    reversibleEncryptionEnabled: {
      value: o.ReversibleEncryptionEnabled
    },
    lockout: {
      threshold: {
        value: o.LockoutThreshold
      },
      duration: {
        value: o.LockoutDuration.TotalMinutes
      },
      resetCounterAfter: {
        value: o.LockoutObservationWindow.TotalMinutes
      }
    }
  };
};

export default passwordPolicy;
