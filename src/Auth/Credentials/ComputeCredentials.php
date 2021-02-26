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

namespace Google\Auth\Credentials;

use Google\Auth\Compute;
use Google\Auth\SignBlob\SignBlobInterface;
use Google\Http\ClientInterface;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;

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
class ComputeCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    /**
     * The metadata path of the default token.
     */
    private const ACCESS_TOKEN_URI_PATH = '/computeMetadata/v1/instance/service-accounts/default/token';

    /**
     * The metadata path of the default id token.
     */
    private const ID_TOKEN_URI_PATH = '/computeMetadata/v1/instance/service-accounts/default/identity';

    /**
     * The metadata path of the client ID.
     */
    private const CLIENT_EMAIL_URI_PATH = '/computeMetadata/v1/instance/service-accounts/default/email';

    /**
     * The metadata path of the project ID.
     */
    private const PROJECT_ID_URI_PATH = '/computeMetadata/v1/project/project-id';

    /**
     * @var string|null
     */
    private $clientEmail;

    /**
     * @var string|null
     */
    private $projectId;

    /**
     * @var string|null
     */
    private $targetAudience;

    /**
     * @var array|null
     */
    private $scope;

    /**
     * @var string|null
     */
    private $quotaProject;

    /**
     * @var string|null
     */
    private $serviceAccountIdentity;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var string
     */
    private $tokenUri;

    /**
     * @var string
     */
    private $compute;

    /**
     * @param array $options {
     *     @type string|array $scope the scope of the access request,
     *         expressed either as an array or as a space-delimited string.
     *     @type string $targetAudience The audience for the ID token.
     *     @type string $quotaProject Specifies a project to bill for access
     *         charges associated with the request.
     *     @type string $serviceAccountIdentity [optional] Specify a service
     *         account identity name to use instead of "default".
     * }
     */
    public function __construct(array $options = [])
    {
        $options += [
            'httpClient' => null,
            'quotaProject' => null,
            'serviceAccountIdentity' => null,
            'scope' => null,
            'targetAudience' => null,
        ];

        if (isset($options['scope']) && isset($options['targetAudience'])) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }

        $this->setCacheFromOptions($options);
        $this->setHttpClientFromOptions($options);

        $this->quotaProject = $options['quotaProject'];
        $this->serviceAccountIdentity = $options['serviceAccountIdentity'];
        $this->scope = is_string($options['scope'])
            ? explode(' ', $options['scope'])
            : $options['scope'];
        $this->targetAudience = $options['targetAudience'];
        $this->tokenUri = $this->getAuthTokenUriPath();
        $this->compute = new Compute();
    }

    /**
     * Implements CredentialsInterface#fetchAuthToken.
     *
     * Fetches the auth tokens from the GCE metadata host if it is available.
     * If $httpClient is not specified a the default HttpHandler is used.
     *
     * @param ClientInterface $httpClient callback which delivers psr7 request
     *
     * @return array A set of auth related metadata, based on the token type.
     *
     * Access tokens have the following keys:
     *   - access_token (string)
     *   - expires_in (int)
     *   - token_type (string)
     * ID tokens have the following keys:
     *   - id_token (string)
     *
     * @throws \Exception
     */
    private function fetchAuthTokenNoCache(): array
    {
        $response = $this->compute->getFromMetadata($this->tokenUri);

        if ($this->targetAudience) {
            $exp = $this->jwtClient->getExpirationWithoutVerification($response);
            return [
                'id_token' => $response,
                'expires_at' => $exp,
            ];
        }

        if (null === $json = json_decode($response, true)) {
            throw new \Exception('Invalid JSON response');
        }

        $json['expires_at'] = time() + $json['expires_in'];

        return $json;
    }

    /**
     * Get the client name from GCE metadata.
     *
     * Subsequent calls will return a cached value.
     *
     * @return string
     */
    public function getClientEmail(): string
    {
        if ($this->clientEmail) {
            return $this->clientEmail;
        }

        return $this->clientEmail = $this->compute->getFromMetadata(
            self::getClientEmailUriPath($this->serviceAccountIdentity)
        );
    }

    /**
     * Sign a string using the default service account private key.
     *
     * This implementation uses IAM's signBlob API.
     *
     * @see https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/signBlob SignBlob
     *
     * @param string $stringToSign The string to sign.
     * @return string
     */
    public function signBlob(string $stringToSign): string
    {
        $accessToken = $this->fetchAuthToken()['access_token'];

        return $this->signBlobWithServiceAccountApi(
            $this->getClientEmail(),
            $accessToken,
            $stringToSign,
            $this->httpClient
        );
    }

    /**
     * Fetch the default Project ID from compute engine.
     *
     * Returns null if called outside GCE.
     *
     * @return string|null
     */
    public function getProjectId(): ?string
    {
        if ($this->projectId) {
            return $this->projectId;
        }

        return $this->projectId = $this->compute->getFromMetadata(
            self::PROJECT_ID_URI_PATH
        );
    }

    /**
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
    }

    private function getCacheKey(): string
    {
        return $this->tokenUri;
    }

    /**
     * The uri path for accessing the auth token.
     *
     * @return string
     */
    private function getAuthTokenUriPath(): string
    {
        if ($this->targetAudience) {
            $uriPath = self::ID_TOKEN_URI_PATH;
            $uriPath .= '?audience=' . $this->targetAudience;
        } else {
            $uriPath = self::ACCESS_TOKEN_URI_PATH;
            if ($this->scope) {
                $uriPath .= '?scopes=' . implode(',', $this->scope);
            }
        }

        if ($this->serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $this->serviceAccountIdentity . '/',
                $uriPath
            );
        }

        return $uriPath;
    }

    /**
     * The full uri for accessing the default service account.
     *
     * @param string $serviceAccountIdentity [optional] Specify a service
     *   account identity name to use instead of "default".
     * @return string
     */

    private static function getClientEmailUriPath(
        string $serviceAccountIdentity = null
    ): string {
        $uriPath = self::CLIENT_EMAIL_URI_PATH;

        if ($serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $serviceAccountIdentity . '/',
                $uriPath
            );
        }

        return $uriPath;
    }
}
