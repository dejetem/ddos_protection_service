# DDoS Protection Service

A comprehensive DDoS protection and traffic management system for web applications, built with Rust and integrated with Cloudflare's services.

## Features

- Rate limiting and traffic analysis
- IP blacklisting and whitelisting
- Cloudflare integration for DDoS mitigation
- Real-time traffic monitoring and analytics
- RESTful API for configuration and monitoring
- Prometheus metrics export
- Comprehensive logging

## Architecture

The service is built with a modular architecture that separates concerns into distinct components:

- **Core**: Rate limiting, IP management, and traffic analysis
- **Cloudflare Integration**: API client and rule management
- **API Layer**: REST endpoints for configuration and monitoring
- **Metrics & Logging**: Observability and monitoring

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Redis (for rate limiting and caching)
- Cloudflare API credentials

### Configuration

Create a `.env` file in the project root:

```env
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ZONE_ID=your_zone_id
REDIS_URL=redis://localhost:6379
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
```

### Building

```bash
cargo build --release
```

### Running

```bash
cargo run --release
```

## API Documentation

The service exposes a REST API for configuration and monitoring. See [API Documentation](docs/api.md) for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 