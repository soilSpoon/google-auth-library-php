<?php
/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

namespace Google\Auth;

use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use Google\Auth\SignBlob\SignBlobInterface;
use Google\Http\ClientInterface;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Client\ClientExceptionInterface;

/**
 * ComputeCredentials supports authorization on Google Compute Engine.
 *
 * It can be used to authorize requests using the AuthTokenMiddleware, but will
 * only succeed if being run on GCE:
 *
 *   use Google\Auth\Credentials\ComputeCredentials;
 *   use Google\Auth\Http\CredentialsClient;
 *   use Psr\Http\Message\Request;
 *
 *   $gce = new ComputeCredentials();
 *   $http = new CredentialsClient($gce);
 *
 *   $url = 'https://www.googleapis.com/taskqueue/v1beta2/projects';
 *   $res = $http->send(new Request('GET', $url));
 */
class Compute implements SignBlobInterface
{
    use ServiceAccountApiSignBlobTrait;

    /**
     * The metadata IP address on appengine instances.
     *
     * The IP is used instead of the domain 'metadata' to avoid slow responses
     * when not on Compute Engine.
     */
    private const METADATA_IP = '169.254.169.254';

    /**
     * The header whose presence indicates GCE presence.
     */
    private const FLAVOR_HEADER = 'Metadata-Flavor';

    /**
     * Determines if this an App Engine Flexible instance, by accessing the
     * GAE_INSTANCE environment variable.
     *
     * @return bool
     */
    public static function onAppEngineFlexible(): bool
    {
        if ($gaeInstance = getenv('GAE_INSTANCE')) {
            return substr($gaeInstance, 0, 4) === 'aef-';
        }
        return false;
    }

    /**
     * Determines if this a GCE instance, by accessing the expected metadata
     * host.
     *
     * @param ClientInterface $httpClient
     * @return bool
     */
    public static function onCompute(ClientInterface $httpClient): bool
    {
        /**
         * Note: the explicit `timeout` and `tries` below is a workaround. The underlying
         * issue is that resolving an unknown host on some networks will take
         * 20-30 seconds; making this timeout short fixes the issue, but
         * could lead to false negatives in the event that we are on GCE, but
         * the metadata resolution was particularly slow. The latter case is
         * "unlikely" since the expected 4-nines time is about 0.5 seconds.
         * This allows us to limit the total ping maximum timeout to 1.5 seconds
         * for developer desktop scenarios.
         */
        $maxComputePingTries = 3;
        $computePingConnectionTimeoutSeconds = 0.5;
        $checkUri = 'http://' . self::METADATA_IP;
        for ($i = 1; $i <= $maxComputePingTries; $i++) {
            try {
                // Comment from: oauth2client/client.py
                //
                // Note: the explicit `timeout` below is a workaround. The underlying
                // issue is that resolving an unknown host on some networks will take
                // 20-30 seconds; making this timeout short fixes the issue, but
                // could lead to false negatives in the event that we are on GCE, but
                // the metadata resolution was particularly slow. The latter case is
                // "unlikely".
                $resp = $httpClient->send(
                    new Request(
                        'GET',
                        $checkUri,
                        [self::FLAVOR_HEADER => 'Google']
                    ),
                    ['timeout' => $computePingConnectionTimeoutSeconds]
                );

                return $resp->getHeaderLine(self::FLAVOR_HEADER) == 'Google';
            } catch (ClientExceptionInterface $e) {
            }
        }
        return false;
    }

    /**
     * Fetch the value of a GCE metadata server URI.
     *
     * @param string $uriPath The metadata URI path.
     * @return string
     */
    public function getFromMetadata(string $uriPath): string
    {
        $uri = 'http://' . self::METADATA_IP . $uriPath;

        $resp = $this->httpClient->send(
            new Request(
                'GET',
                $uri,
                [self::FLAVOR_HEADER => 'Google']
            )
        );

        return (string) $resp->getBody();
    }
}
