# hr-payroll-ai
IBM 5기 3팀 인사 급여 프로젝트
팀명: 갓생코더

로컬 설치 순서는 [설치 가이드](docs/설치-가이드.md)를 따릅니다.

프론트엔드 문서는 [control-web](frontends/control-web/README.md)과 [hr-web](frontends/hr-web/README.md)에 있습니다.

## 개발 환경

| 구분 | 기술 스택 |
|------|-----------|
| 언어 / 런타임 | Java 21, Node.js 22 |
| 서비스 API | Spring Boot 4, Spring MVC |
| 보안 | Spring Security 7, JWT |
| 설정 전파 | Spring Cloud Bus + RabbitMQ |
| RDBMS | PostgreSQL 17 + pgvector |
| 캐시 | Redis |
| 서비스 간 통신 | gRPC (동기), Kafka (비동기, KRaft) |
| Frontend | React + Vite + React Router + Tailwind CSS 4 |
| CI/CD 파이프라인 | ArgoCD |
| 컨테이너화 및 배포 | Docker + Kubernetes |
| 컨테이너 오케스트레이션 | OpenShift |
| 모니터링 및 대시보드 | Prometheus + Grafana, Elasticsearch + Kibana |
| 오브젝트 스토리지 | 로컬 Garage, 배포 AWS S3 |
| Git 저장소 | Github |
| AI | Python FastAPI, Gemini RAG, Tool Calling, LangChain, LangGraph |
| AI 연동 | MCP 프로토콜 |