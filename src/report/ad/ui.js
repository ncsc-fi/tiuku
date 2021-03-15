import Col from 'react-bootstrap/Col';
import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import DomainOverview from './domainOverview/ui';
import PasswordPolicy from './passwordPolicy/ui';
import DomainAdmins from './domainAdmins/ui';
import KrbtgtUsers from './krbtgtUsers/ui';

const Report = ({report}) => (
  <div>
    <Container className="mt-3">
      <Row>
        <Col>
          <DomainOverview domainOverview={report.domainOverview}/>
        </Col>
      </Row>
    </Container>
    <Container className="mt-3">
      <Row>
        <Col>
          <PasswordPolicy passwordPolicy={report.passwordPolicy}/>
        </Col>
      </Row>
    </Container>
    <Container className="mt-3">
      <Row>
        <Col>
        <DomainAdmins domainAdmins={report.domainAdmins} />
        </Col>
      </Row>
    </Container>
    <Container className="mt-3">
      <Row>
        <Col>
          <KrbtgtUsers krbtgtUsers={report.krbtgtUsers} />
        </Col>
      </Row>
    </Container>
    </div>
);

export default Report;
