import issues from './issues.json';
import {
  emptyIssues
} from '../../common/analyzer';
import {analyzeKrbtgtUser} from './analyzer';

describe('analyzeKrbtgtUser', () => {
  it('alerts if the password has last been changed over a year ago', () => {
    const passwordChanged = new Date();
    passwordChanged.setFullYear(passwordChanged.getFullYear() - 1);
    const input = {passwordChanged};
    const result = analyzeKrbtgtUser(input);
    expect(result).toEqual({
      ...input,
      issues: {
        ...emptyIssues,
        alerts: [issues.PASSWORD_TOO_OLD]
      }
    });
  });

  it('considers the password OK otherwise', () => {
    const passwordChanged = new Date();
    // Just a day under one year.
    passwordChanged.setFullYear(passwordChanged.getFullYear() - 1);
    passwordChanged.setDate(passwordChanged.getDate() + 1);
    const input = {passwordChanged};
    const result = analyzeKrbtgtUser(input);
    expect(result).toEqual({
      ...input,
      issues: emptyIssues
    });
  });
});
