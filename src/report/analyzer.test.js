import m365UsersIssues from './m365/users/issues.json';
import adPasswordPolicyIssues from './ad/passwordPolicy/issues.json';
import adKrbtgtUsersIssues from './ad/krbtgtUsers/issues.json';
import * as ReportType from './ReportType';
import {emptyIssues} from './common/analyzer';
import {
  analyzeReport,
} from './analyzer';

describe('analyzeReport', () => {
  it('can analyze M365 reports', () => {
    const report = {
      reportType: ReportType.M365,
      users: [
        {
          displayName: 'Alice',
          userPrincipalName: 'alice@example.com',
          mfaState: 'Disabled'
        }
      ]
    };
    const result = analyzeReport(report);
    expect(result).toEqual({
      reportType: ReportType.M365,
      users: [
        {
          displayName: 'Alice',
          userPrincipalName: 'alice@example.com',
          mfaState: 'Disabled',
          issues: {
            ...emptyIssues,
            alerts: [m365UsersIssues.MFA_DISABLED]
          }
        }
      ]
    });
  });

  it('can analyze AD reports', () => {
    const report = {
      reportType: ReportType.AD,
      passwordPolicy: {
        minLength: {
          value: 10
        },
        historySize: {
          value: 1
        },
        complexityCheckEnabled: {
          value: false
        },
        reversibleEncryptionEnabled: {
          value: true
        },
        lockout: {
          duration: {
            value: 1
          },
          threshold: {
            value: 100
          },
          resetCounterAfter: {
            value: 1
          }
        }
      },
      krbtgtUsers: [
        {
          passwordChanged: new Date(Date.parse('2018-12-17T09:45:00.526Z'))

        }
      ]
    };
    const result = analyzeReport(report);
    expect(result).toEqual({
      reportType: ReportType.AD,
      passwordPolicy: {
        minLength: {
          value: 10,
          issues: {
            ...emptyIssues,
            warnings: [adPasswordPolicyIssues.MIN_LENGTH_TOO_SHORT]
          }
        },
        historySize: {
          value: 1,
          issues: {
            ...emptyIssues,
            warnings: [adPasswordPolicyIssues.HISTORY_SIZE_TOO_SMALL]
          }
        },
        complexityCheckEnabled: {
          value: false,
          issues: {
            ...emptyIssues,
            warnings: [adPasswordPolicyIssues.COMPLEXITY_CHECK_DISABLED]
          }
        },
        reversibleEncryptionEnabled: {
          value: true,
          issues: {
            ...emptyIssues,
            alerts: [adPasswordPolicyIssues.REVERSIBLE_ENCRYPTION_ENABLED]
          }
        },
        lockout: {
          duration: {
            value: 1,
            issues: {
              ...emptyIssues,
              warnings: [adPasswordPolicyIssues.LOCKOUT_DURATION_TOO_SHORT]
            }
          },
          threshold: {
            value: 100,
            issues: {
              ...emptyIssues,
              warnings: [adPasswordPolicyIssues.LOCKOUT_THRESHOLD_TOO_HIGH]
            }
          },
          resetCounterAfter: {
            value: 1,
            issues: {
              ...emptyIssues,
              warnings: [adPasswordPolicyIssues.LOCKOUT_RESET_COUNTER_AFTER_TOO_SHORT]
            }
          },
        }
      },
      krbtgtUsers: [
        {
          passwordChanged: new Date(Date.parse('2018-12-17T09:45:00.526Z')),
          issues: {
            ...emptyIssues,
            alerts: [adKrbtgtUsersIssues.PASSWORD_TOO_OLD]
          }
        }
      ]
    });
  });
});
