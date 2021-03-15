import issues from './issues.json';
import {
  analyzer,
  arrayAnalyzer
} from '../../common/analyzer';

export const analyzeUser = analyzer(({mfaState}) => {
  if (mfaState === 'Disabled') {
    return {
      alerts: [issues.MFA_DISABLED]
    };
  } else if (mfaState === 'Enabled') {
    return {
      warnings: [issues.MFA_NOT_ENFORCED]
    };
  }
});

const analyzeUsers = arrayAnalyzer(analyzeUser);

export default analyzeUsers;
