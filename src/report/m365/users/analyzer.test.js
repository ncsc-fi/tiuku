import issues from './issues.json';
import {emptyIssues} from '../../common/analyzer';
import {
  analyzeUser
} from './analyzer';

describe('analyzeUser', () => {
  it("alerts if the user doesn't have MFA enabled", () => {
    const input = {
      displayName: 'Alice',
      userPrincipalName: 'alice@example.com',
      mfaState: 'Disabled'
    };
    const result = analyzeUser(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        alerts: [issues.MFA_DISABLED]
      }
    });
  });

  it("warns if the user doesn't have MFA enforced", () => {
    const input = {
      displayName: 'Alice',
      userPrincipalName: 'alice@example.com',
      mfaState: 'Enabled'
    };
    const result = analyzeUser(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        warnings: [issues.MFA_NOT_ENFORCED],
      }
    });
  });

  it('considers the user OK otherwise', () => {
    const input = {
      displayName: 'Alice',
      userPrincipalName: 'alice@example.com',
      mfaState: 'Enforced'
    };
    const result = analyzeUser(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});
