import issues from './issues.json';
import {
  analyzer,
  arrayAnalyzer
} from '../../common/analyzer';

export const analyzeKrbtgtUser = analyzer(({passwordChanged}) => {
  const yearAgo = new Date();
  yearAgo.setFullYear(yearAgo.getFullYear() - 1);

  if (passwordChanged <= yearAgo) {
    return {
      alerts: [issues.PASSWORD_TOO_OLD]
    };
  }
});

const analyzeKrbtgtUsers = arrayAnalyzer(analyzeKrbtgtUser);

export default analyzeKrbtgtUsers;
