import {strongAuthenticationRequirements} from './parser';

describe('strongAuthenticationRequirements', () => {
  it('returns the first requirement if the input is a non-empty array of requirements', () => {
    const context = 'some.context';
    const input = [
      {State: 'Enabled'},
      {State: 'Disabled'}
    ];
    const result = strongAuthenticationRequirements(context, input);
    expect(result).toEqual({mfaState: 'Enabled'});
  });

  it('returns a requirement with MFA disabled if the input is an empty array', () => {
    const context = 'some.context';
    const input = [];
    const result = strongAuthenticationRequirements(context, input);
    expect(result).toEqual({mfaState: 'Disabled'});
  });
});
