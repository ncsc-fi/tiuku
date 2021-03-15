import {useState} from 'react';
import ReportAd from './report/ad/ui';
import ReportM365 from './report/m365/ui';
import ReportLinux from './report/linux/ui';
import * as ReportType from './report/ReportType';
import {parseReport} from './report/parser';
import {analyzeReport} from './report/analyzer';

const Report = ({report}) => {
  if (report === null) {
    return (
      <div className="flex-grow-1 d-flex justify-content-center align-items-center lead border border-dashed border-5px rounded m-5">
        <ul className="list-group list-group-flush">
          <li className="list-group-item">Run a data collector script from the collectors directory.</li>
          <li className="list-group-item">Drag and drop the created JSON file here.</li>
        </ul>
      </div>
    );
  } else if (report.reportType === ReportType.M365) {
    return (
      <ReportM365 report={report} />
    );
  } else if (report.reportType === ReportType.AD) {
    return (
      <ReportAd report={report} />
    );
  } else if (report.reportType === ReportType.LINUX) {
    return (
      <ReportLinux report={report} />
    );
  } else {
    throw new Error(`Unexpected report type: ${report.reportType}`);
  };
};

const App = () => {
  const [report, setReport] = useState(null);

  const onDragOver = (e) => {
    e.stopPropagation();
    e.preventDefault();
  };

  const onDrop = (e) => {
    const files = e.dataTransfer.files;
    const reader = new FileReader();
    reader.readAsText(files[0]);

    reader.onload = (read) => {
      const reportSrc = read.target.result;
      try {
        const report = parseReport(reportSrc);
        setReport(analyzeReport(report));
      } catch (e) {
        alert(e.message);
        console.error(e);
      }
    };

    e.stopPropagation();
    e.preventDefault();
  };

  return (
    <div onDragOver={onDragOver} onDrop={onDrop} className="flex-grow-1 d-flex flex-column">
      <Report report={report} />
    </div>
  );
};

export default App;
