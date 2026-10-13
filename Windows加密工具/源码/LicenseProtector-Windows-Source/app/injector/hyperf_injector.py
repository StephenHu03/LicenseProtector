"""Hyperf-specific runtime injection for generated customer releases."""

from __future__ import annotations

import re
from pathlib import Path


class HyperfInjector:
    """Install a per-request guard because Hyperf's bootstrap runs in CLI."""

    middleware_class = r"\App\Middleware\LicenseProtectorMiddleware::class"

    native_middleware_class = r"\App\Middleware\NativeLicenseProtectorMiddleware::class"

    def inject(self, project_root: Path) -> list[Path]:
        """Create and register a middleware before all customer HTTP middleware.

        The generated file belongs only to the delivery copy. It deliberately
        uses ``require`` instead of ``require_once`` so the Watchdog validates
        every request in a long-running Hyperf worker.
        """
        middleware = project_root / "app" / "Middleware" / "LicenseProtectorMiddleware.php"
        config = project_root / "config" / "autoload" / "middlewares.php"
        if not config.is_file():
            raise FileNotFoundError("Hyperf middleware configuration not found")

        middleware.parent.mkdir(parents=True, exist_ok=True)
        middleware.write_text(
            """<?php

declare(strict_types=1);

namespace App\\Middleware;

use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Psr\\Http\\Server\\MiddlewareInterface;
use Psr\\Http\\Server\\RequestHandlerInterface;
use Hyperf\\HttpServer\\Contract\\ResponseInterface as HyperfResponse;

/** Validates the signed license against the Host of every Hyperf request. */
final class LicenseProtectorMiddleware implements MiddlewareInterface
{
    public function __construct(private HyperfResponse $response)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // PHP includes inherit this method's scope, which safely supplies the
        // request Host without sharing state between Hyperf coroutines.
        $__lp_request_host = $request->getHeaderLine('Host');
        try {
            require dirname(__DIR__, 2) . '/protected/watchdog/loader.php';
        } catch (\\RuntimeException $exception) {
            $message = $exception->getMessage();
            if (!str_starts_with($message, 'License validation failed (LIC-')) {
                throw $exception;
            }
            return $this->response->json([
                'message' => 'License validation failed',
                'code' => substr($message, 27, 8),
            ])->withStatus(403);
        }

        return $handler->handle($request);
    }
}
""",
            encoding="utf-8",
            newline="\n",
        )

        text = config.read_text(encoding="utf-8")
        if self.middleware_class not in text:
            text, count = re.subn(
                r"(['\"]http['\"]\s*=>\s*\[)",
                lambda match: match.group(1) + "\n        " + self.middleware_class + ",",
                text,
                count=1,
            )
            if count != 1:
                raise ValueError("Unable to register Hyperf HTTP middleware safely")
            config.write_text(text, encoding="utf-8", newline="\n")
        return [middleware, config]

    def inject_native(self, project_root: Path) -> list[Path]:
        """Register a request guard that asks the native Agent to validate Host."""
        middleware = project_root / "app" / "Middleware" / "NativeLicenseProtectorMiddleware.php"
        config = project_root / "config" / "autoload" / "middlewares.php"
        if not config.is_file():
            raise FileNotFoundError("Hyperf middleware configuration not found")
        middleware.parent.mkdir(parents=True, exist_ok=True)
        middleware.write_text(
            r'''<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Hyperf\HttpServer\Contract\ResponseInterface as HyperfResponse;

/** Performs a strict per-request domain/IP check through the local Agent. */
final class NativeLicenseProtectorMiddleware implements MiddlewareInterface
{
    public function __construct(private HyperfResponse $response)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $socket = getenv('LP_AGENT_SOCKET') ?: '/run/license-protector/agent.sock';
        $manifest = dirname(__DIR__, 2) . '/protected/lpbc/manifest.json';
        $payload = json_encode([
            'protocol' => 'LP-AGENT-1',
            'op' => 'validate',
            'host' => $request->getHeaderLine('Host'),
            'manifest_sha256' => is_file($manifest) ? hash_file('sha256', $manifest) : '',
        ], JSON_UNESCAPED_SLASHES);
        $connection = @stream_socket_client('unix://' . $socket, $errno, $error, 2);
        if (!is_resource($connection) || !is_string($payload)) {
            return $this->response->json(['message' => 'License validation failed', 'code' => 'LIC-1003'])->withStatus(403);
        }
        stream_set_timeout($connection, 2);
        fwrite($connection, $payload . "\n");
        $answer = json_decode((string) fgets($connection), true);
        fclose($connection);
        if (!is_array($answer) || ($answer['ok'] ?? false) !== true) {
            return $this->response->json(['message' => 'License validation failed', 'code' => 'LIC-1003'])->withStatus(403);
        }
        return $handler->handle($request);
    }
}
''',
            encoding="utf-8",
            newline="\n",
        )
        text = config.read_text(encoding="utf-8")
        if self.native_middleware_class not in text:
            text, count = re.subn(
                r"(['\"]http['\"]\s*=>\s*\[)",
                lambda match: match.group(1) + "\n        " + self.native_middleware_class + ",",
                text,
                count=1,
            )
            if count != 1:
                raise ValueError("Unable to register native HTTP middleware safely")
            config.write_text(text, encoding="utf-8", newline="\n")
        return [middleware, config]
