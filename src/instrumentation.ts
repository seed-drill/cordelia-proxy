/**
 * Observability instrumentation for Cordelia
 *
 * Configure with environment variables:
 *   SENTRY_DSN: Sentry DSN for error tracking
 *   HONEYCOMB_API_KEY: Your Honeycomb API key
 *   OTEL_SERVICE_NAME: Service name (default: cordelia)
 *   HONEYCOMB_DATASET: Dataset name (default: cordelia)
 */

import * as Sentry from '@sentry/node';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { diag, DiagConsoleLogger, DiagLogLevel } from '@opentelemetry/api';

const SENTRY_DSN = process.env.SENTRY_DSN;
const HONEYCOMB_API_KEY = process.env.HONEYCOMB_API_KEY;
const SERVICE_NAME = process.env.OTEL_SERVICE_NAME || 'cordelia';
const HONEYCOMB_DATASET = process.env.HONEYCOMB_DATASET || 'cordelia';

// Enable debug logging if needed
if (process.env.OTEL_DEBUG === 'true') {
  diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.DEBUG);
}

let sdk: NodeSDK | null = null;
let sentryInitialized = false;

function initSentry(): void {
  if (!SENTRY_DSN) {
    console.log('Cordelia: Sentry error tracking disabled (no SENTRY_DSN)');
    return;
  }

  Sentry.init({
    dsn: SENTRY_DSN,
    environment: process.env.FLY_APP_NAME ? 'production' : 'development',
    release: `cordelia@0.4.0`,
    tracesSampleRate: 0.1,
    // Only send errors in production by default
    beforeSend(event) {
      // Filter out expected errors if needed
      return event;
    },
  });

  sentryInitialized = true;
  console.log('Cordelia: Sentry error tracking initialized');
}

export function initTelemetry(): void {
  // Initialize Sentry first for error tracking
  initSentry();

  if (!HONEYCOMB_API_KEY) {
    console.log('Cordelia: Honeycomb monitoring disabled (no HONEYCOMB_API_KEY)');
    return;
  }

  console.log(`Cordelia: Initializing Honeycomb telemetry for ${SERVICE_NAME}`);

  const traceExporter = new OTLPTraceExporter({
    url: 'https://api.honeycomb.io/v1/traces',
    headers: {
      'x-honeycomb-team': HONEYCOMB_API_KEY,
      'x-honeycomb-dataset': HONEYCOMB_DATASET,
    },
  });

  sdk = new NodeSDK({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: SERVICE_NAME,
      [ATTR_SERVICE_VERSION]: '0.4.0',
      'deployment.environment': process.env.FLY_APP_NAME ? 'production' : 'development',
      'fly.app': process.env.FLY_APP_NAME || 'local',
      'fly.region': process.env.FLY_REGION || 'local',
    }),
    traceExporter,
    instrumentations: [
      getNodeAutoInstrumentations({
        // Disable fs instrumentation (too noisy)
        '@opentelemetry/instrumentation-fs': { enabled: false },
        // Configure HTTP instrumentation
        '@opentelemetry/instrumentation-http': {
          ignoreIncomingRequestHook: (req) => {
            // Ignore health checks
            return req.url === '/health' || req.url === '/api/status';
          },
        },
      }),
    ],
  });

  sdk.start();
  console.log('Cordelia: Honeycomb telemetry initialized');

  // Graceful shutdown
  process.on('SIGTERM', () => {
    Promise.all([
      sdk?.shutdown(),
      sentryInitialized ? Sentry.close(2000) : Promise.resolve(),
    ])
      .then(() => console.log('Cordelia: Telemetry shut down'))
      .catch((err) => console.error('Cordelia: Telemetry shutdown error', err))
      .finally(() => process.exit(0));
  });
}

export async function shutdownTelemetry(): Promise<void> {
  await Promise.all([
    sdk?.shutdown(),
    sentryInitialized ? Sentry.close(2000) : Promise.resolve(),
  ]);
}

// Re-export Sentry for use in error handlers
export { Sentry };
