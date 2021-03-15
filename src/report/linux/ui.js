import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import Superusers from './superusers/ui';

const ReportLinux = ({report}) => (
  <div>
    <Container className="mt-3">
      <Row>
        <Col>
          <Superusers superusers={report.superusers} />
        </Col>
      </Row>
    </Container>
  </div>
);

export default ReportLinux;
