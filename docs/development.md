# Development guide

## Development environment

### Requirements

* [Docker](https://www.docker.com/get-started)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Development server

You can start the development server with the following command:

    docker-compose up

To stop the server, press `Ctrl+C`. Once you no longer need the server, you can free up disk space by removing it completely with:

    docker-compose down

### NPM

To run NPM commands (such as `npm` and `npx`), start a new shell in a Docker container:

    docker-compose run --rm dev sh

### Unit tests

You can run the unit tests with the following command:

    docker-compose run --rm dev npm test
    
Press `q` to stop the test runner.

### Production build

The script `build.sh` creates a production build of the UI and the data retrieval scripts in the `release` directory. You can run it in a Docker container with the following command:

    docker-compose run --rm dev ./build.sh

## Extending the project

There are four steps in which data moves from the world into the user interface, each handled by a dedicated component:

1. A [collector](#collecting-data) collects the data from some data source and writes it into a report file.
2. A [parser](#parsing-the-data) reads the report file, validates its contents, and turns them into a data structure used in the following steps.
3. An [analyzer](#analyzing-the-data) checks the data for issues that should be displayed to the user as warnings and alerts.
4. A [UI component](#displaying-the-data) displays the data and issues.

### Collecting data

The user interface displays *reports* &ndash; JSON files with data about the system or environment that's being inspected. The reports are created by running *collectors* &ndash; scripts that know how to collect data from a particular data source (e.g. there's one collector for M365 and another for internal AD environments).

If you want to fetch some additional data from a data source for which a collector already exists, you can modify the existing collector. Otherwise, you will have to create a new collector that knows how to talk to the new data source.

#### Extending a PowerShell-based collector

Each PowerShell-based collector has a main script in `collectors/<name>/libs/main.ps1`. The script is split into functions, each retrieving a set of data that corresponds to a single section of the user interface. To collect data for a new section, create a new function that returns a hash table with two keys: `Type` and `Data`. `Type` names the key under which the data will be placed in the report data structure, and `Data` contains the actual data.

For example, if your new function collects data about the virtual machines in the environment, it could look like this:

```ps1
function Get-VirtualMachines() {
    return @{
        Type = "VirtualMachines"
        Data = @(... some powershell command that digs up data about virtual machines ...)
    }
}
```

---

**PowerShell gotcha!** If you're expecting a command to return an array, make sure you wrap it in `@( )`. Otherwise "no results" will be returned as `null` instead of an empty array, and a single result will be returned directly and not an array with a single element.

---

You also need to list the function's name in the variable `$EnabledModules` at the beginning of the script so it gets run when the collector is executed:

```ps1
[array]$EnabledModules = @(
    # ... other function names ...
    'Get-VirtualMachines'
)
```

Now a new key will be included in the report file:

```js
{
  // ...
  "VirtualMachines": [
    // ... the data returned by your function ...
  ]
}
```

#### Creating a new collector

The only hard requirement for collectors is that they need to produce JSON files, so in theory collectors can be implemented using any technology, but it's best if they have as little dependencies as possible. Ideally, users should be able to run the collectors without installing any new programs on their operating system. For example, the AD and M365 collectors are written to run on the version of PowerShell that ships with Windows 10.
 
If you would like to contribute your collector to be merged into the project, try to follow the technology choices and structure used by the existing collectors if possible.

Make sure the report files produced by your collector contain a `ReportType` key identifying the collector. For example, if your collector's data source is Fictional Cloud, your report file should look like this:

```js
{
  "ReportType": "FICTIONAL_CLOUD",
  // ...
}
```

### Parsing the data

Collectors are meant to be as thin wrappers over existing data collection tools as possible, so they only do a minimal amount of formatting and mostly write data into the report exactly as it was produced by some tool or command. When the report is loaded into the user interface, it is read by a *parser* that both validates that it is in the expected format and transforms it into an internal representation that is easier to work with.

> Consider: what is a parser? Really, a parser is just a function that consumes less-structured input and produces more-structured output. By its very nature, a parser is a partial function—some values in the domain do not correspond to any value in the range—so all parsers must have some notion of failure. Often, the input to a parser is text, but this is by no means a requirement, and parseNonEmpty is a perfectly cromulent parser: it parses lists into non-empty lists, signaling failure by terminating the program with an error message.

> Under this flexible definition, parsers are an incredibly powerful tool: they allow discharging checks on input up-front, right on the boundary between a program and the outside world, and once those checks have been performed, they never need to be checked again!

*&mdash; Alexis King, [Parse, don't validate](https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/)*

#### Parser functions

All the parsers in the project, including the ones you'll be writing for your data, are functions that take an unknown object `x`, and either transform the data in `x` into an internal representation or fail because the value of `x` wasn't expected in the given context. In addition to `x`, the parsers also take a `context` argument that tells them where in the input document `x` was found, so they can produce more meaningful error messages. For example, if `x` was the third virtual machine in the report, `context` would be `".VirtualMachines[2]"`

Most of the project's higher-level parsers work in two steps:

1. Parse the input using other, lower-level parsers.
2. Transform the result into an internal representation that's easier to work with.

Let's suppose the data collection tool you use to fetch data about virtual machines in Fictional Cloud represents them like this in the JSON file:

```js
{
  "Id": "827666c9-3cd8-4826-8c4c-7df34e1a1e19",
  "GizmoCount": 3,
  "Metadata": {
    "Tags": [
      {
        "TagName": "Created",
        "TagValue": "2020-07-23"
      },
      {
        "TagName": "HumanReadableName",
        "TagValue": "Reverse proxy #1"
      }
    ]
  }
}
```

And your preferred internal representation would be:
```js
{
  id: "827666c9-3cd8-4826-8c4c-7df34e1a1e19",
  name: "Reverse proxy #1",
  gizmoCount: 3
}
```

In this case you could validate and transform the input data with a custom parser like the following:

```js
const virtualMachine = (context, x) => {
  // Step 1: Parse the input using lower-level parsers into a temporary object `o`.
  const o = struct({
    Id: string,
    GizmoCount number,
    Metadata: struct({
      Tags: arrayOf(struct({
        TagName: string,
        TagValue: string
      }))
    })
  })(context, x);
  
  // Step 2: Transform the data in the temporary object `o` into our preferred representation.
  let name = null;
  for (const tag of o.Metadata.Tags) {
    if (tag.TagName === 'HumanReadableName') {
      name = tag.TagValue;
      break;
    }
  });
  
  return {
    id: o.Id,
    name: name,
    gizmoCount: o.GizmoCount
  }
}
```

In this example `string` and `number` are parsers, and `struct` and `arrayOf` are functions that create parsers based on some specification (the expected structure of an object's properties or an array's elements). They are defined in `src/report/common/parser.js`, and you can find documentation and usage examples for them in `src/report/common/parser.test.js`.

Since the new `virtualMachine` parser implements the standard parser interface, it can be passed as an argument to any function expecting a parser, like `arrayOf`, which takes a parser for a single array element and returns a parser for an array of such elements:

```js
const virtualMachines = arrayOf(virtualMachine);
```

#### Extending the parser for an existing report type

The parser for each report section is located in `src/report/<report type>/<section>/parser.js`. To add a parser for a new "virtual machines" section in the Fictional Cloud report, create a new file called `src/report/fictionalCloud/virtualMachines/parser.js` containing the two parsers `virtualMachine` and `virtualMachines` as described above. Finally, make the parser for the whole section the file's default export:

```js
export default virtualMachines;
```

Next, edit the parser for the whole Fictional Cloud report in `src/report/fictionalCloud/parser.js` and make it use the parser for the new section:

```js
import {struct} from '../common/parser';
// ...
import virtualMachines from './virtualMachines/parser';

const report = (context, x) => {
  const o = struct({
    // ... possibly other properties ...
    VirtualMachines: virtualMachines
  })(context, x);

  return {
    // ... possibly other properties ...
    virtualMachines: o.VirtualMachines
  };
};

export default report;
```

For a real example of section and report parsers, see [`src/report/m365/users/parser.js`](../src/report/m365/users/parser.js) and [`src/report/m365/parser.js`](../src/report/m365/parser.js).

#### Creating a parser for a new report type

Follow the steps for extending an existing report parser, but in a new directory `src/report/<report type>` for the new report type instead of making changes in an existing report type's directory.

Then, edit [`src/report/ReportType.js`](../src/report/ReportType.js) and add a new constant for your report type (it should match the `ReportType` value written by the collector):

```js
// ...
export const FICTIONAL_CLOUD = 'FICTIONAL_CLOUD';
```

Finally, edit the main report parser in [`src/report/parser.js`](../src/report/parser.js) to call your new report parser when the report's type matches the constant added in the previous step:

```js
// ...
import reportFictionalCloud from './fictionalCloud/parser.js';

// ...

export const parseReport = (x) => {
  // ...

  let report;
  if (o.ReportType === ReportType.M365) {
    report = reportM365(context, doc);
  } else if (/* ... */) {
  // ...
  } else if (o.ReportType === ReportType.FICTIONAL_CLOUD) {
    report = reportFictionalCloud(context, doc);
  }

  // ...
};
```

### Analyzing the data

You can write an *analyzer* function to automatically detect and highlight misconfigurations and other issues in the parsed report. Note that this is completely optional &ndash; if you want to show the data as-is without any automatic analysis, you can skip ahead to *Displaying the data*.

Before you can write the analyzer, you need to describe the potential issues in the file `src/report/<report type>/<section>/issues.json`. In the virtual machine example above, you could have issues for the gizmo count being either too low or too high.

```js
{
  "GIZMO_COUNT_ZERO": {
    "name": "The virtual machine has no gizmos",
    "description": "Every virtual machine should have at least one gizmo."
  },
  "GIZMO_COUNT_TOO_HIGH": {
    "name": "The virtual machine has too many gizmos",
    "description": "The virtual machine is practically drowning in gizmos!"
  }
}
```

With the potential issues described, create or edit `src/report/<report type>/<section>/analyzer.js` and add a new function for checking if a virtual machine has any of these issues:

```js
import {
  analyzer,
  arrayAnalyzer
} from '../../common/analyzer';
import issues from './issues.json';

const analyzeVirtualMachine = analyzer(virtualMachine => {
  if (virtualMachine.gizmoCount > 10) {
    return {
      alerts: [issues.GIZMO_COUNT_TOO_HIGH]
    }
  } else if (virtualMachine.gizmoCount > 5) {
    return {
      warnings: [issues.GIZMO_COUNT_TOO_HIGH]
    }
  } else if (virtualMachine.gizmoCount === 0) {
    return {
      alerts: [issues.GIZMO_COUNT_ZERO]
    }
  }
});
```

If there are issues with the virtual machine, the function returns an object describing them. Less serious issues are returned in the `warnings` array, while the more serious ones are returned in `alerts`. Note that the function is wrapped in `analyzer(...)`, which adds some required functionality that we don't want to repeat for every analysis function.

This function only analyzes a single virtual machine but the report section consists of a whole array of them. You can use the function `arrayAnalyzer` to turn an analyzer for a single element into an analyzer for an array:

```js
const analyzeVirtualMachines = arrayAnalyzer(analyzeVirtualMachine);
```

And again, make the function that deals with the whole section the file's default export:

```js
export default analyzeVirtualMachines;
```

Now you can create or edit the analyzer for the whole report type in `src/report/<report type>/analyzer.js` and make it use the new analyzer for the relevant property:

```js
import {propertyMapper} from '../common/analyzer';
import analyzeVirtualMachines from './virtualMachines/analyzer';

const analyze = propertyMapper({
  // ... possibly other properties ...
  virtualMachines: analyzeVirtualMachines
});

export default analyze;
```

For a real example of section and report analyzers, see [`src/report/m365/users/analyzer.js`](../src/report/m365/users/analyzer.js) and [`src/report/m365/analyzer.js`](../src/report/m365/analyzer.js).

#### Creating an analyzer for a new report type

If you create an analyzer for a new report type, also update the main report analyzer in [src/report/analyzer.js](../src/report/analyzer.js) to call the new analyzer when needed:

```js
// ...
import analyzeFictionalCloud from './fictionalCloud/analyzer';

export const analyzeReport = (report) => {
  if (report.reportType === ReportType.M365) {
    return analyzeM365(report);
  } else if (/* ... */) {
  // ...
  } else if (report.reportType === ReportType.FICTIONAL_CLOUD) {
    return analyzeFictionalCloud(report);
  }
};
```

### Displaying the data

Each report and section has a [React](https://reactjs.org/) component for displaying its data. To display a new section, first create a new component for it in `src/report/<report type>/<section>/ui.js`:

```js
import Table from 'react-bootstrap/Table';

import {
  Issues,
  IssuesTr
} from '../../common/ui';

const VirtualMachines = ({virtualMachines}) => {
  return <>
    <h2>Virtual machines</h2>
    <Table>
      <thead>
        <tr>
          <th>Issues</th>
          <th>Name</th>
          <th>Gizmo count</th>
        </tr>
      </thead>
      <tbody>
        {
          virtualMachines.map(virtualMachine => (
            <IssuesTr key={virtualMachine.id} issues={virtualMachine.issues}>
              <td><Issues issues={virtualMachine.issues} /></td>
              <td>{virtualMachine.name}</td>
              <td>{virtualMachine.gizmoCount}</td>
            </IssuesTr>
          ))
        }
      </tbody>
    </Table>
  </>;
};

export default VirtualMachines;
```

If your report section does not have an [analyzer](#analyzing-the-data), and thus there are no issues to display, you can use `<tr>` in place of `<IssuesTr>` and omit the issues column:

```html
<tr key={virtualMachine.id}>
  <td>{virtualMachine.name}</td>
  <td>{virtualMachine.gizmoCount}</td>
</tr>
```

Then, change the report type's component in `src/report/<report type>/ui.js` to use the new section component:

```js
import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import VirtualMachines from './virtualMachines/ui';

const ReportFictionalCloud = ({report}) => (
  <div>
    <!-- ... possibly other sections ... -->

    <Container className="mt-3">
      <Row>
        <Col>
          <VirtualMachines virtualMachines={report.virtualMachines}/>
        </Col>
      </Row>
    </Container>
  </div>
);

export default ReportFictionalCloud;
```

#### Creating a UI component for a new report type

Follow the steps for creating report sections, but create the new file `src/report/<report type>/ui.js` instead of editing an existing one.

Then, edit the file `src/App.js` to use the new report UI component for displaying reports of the new report type.

```js
import ReportAd from './report/ad/ui';
import ReportM365 from './report/m365/ui';
// ...
import ReportFictionalCloud from './report/fictionalCloud/ui';
// ...

const Report = ({report}) => {
  if (report === null) {
    // ...
  } else if (report.reportType === ReportType.M365) {
    // ...
  } else if (/* ... */) {
    // ...
  } else if (report.reportType === ReportType.FICTIONAL_CLOUD) {
    return (
      <ReportFictionalCloud report={report} />
    );
  }
  // ...
};
```
