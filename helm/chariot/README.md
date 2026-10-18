# Epic AI® Chariot — Helm chart

Buyer-deployed packaging for the Chariot IVA MCP Gateway. Implements
CHARIOT-SPEC §23.2 and invariants **CH-24 … CH-30**.

Topology (CH-27): **gateway + MongoDB + Redis only** — the vector store
(Qdrant Edge) is embedded in the gateway image, so there is no separate vector
pod/service. This is the three-image set; MongoDB and Redis ship as vendored
subcharts under `charts/`.

## Delivery options

- **Amazon EKS (primary)** and **EKS-Anywhere / self-managed Kubernetes** (air-gap):
  same chart.
- **Amazon ECS (secondary):** `ecs/chariot-gateway-taskdef.json` (see below).

## Install (EKS)

Credentials are **operator-supplied and fail-closed** (CH-28) — the chart never
defaults or generates a password.

```sh
# 1) Create the gateway secret (sensitive env consumed via envFrom).
kubectl create secret generic chariot-gateway-secret \
  --from-literal=ENTERPRISE_JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=ENTERPRISE_MASTER_KEY="$(openssl rand -base64 32)" \
  --from-literal=MONGODB_URI="mongodb://chariot:<pw>@<release>-mongodb:27017/epicai?authSource=admin" \
  --from-literal=REDIS_URL="redis://:<pw>@<release>-redis:6379"

# 2) Install. Mongo/Redis passwords must match the URIs above. The chart aborts
#    unless an image registry resolves (CH-29: never Docker Hub); the published
#    Marketplace chart already carries it, a source checkout needs it set.
helm install chariot ./helm/chariot \
  --set global.imageRegistry=<acct>.dkr.ecr.<region>.amazonaws.com \
  --set gateway.existingSecret=chariot-gateway-secret \
  --set mongodb.auth.rootPassword='<pw>' \
  --set redis.auth.password='<pw>'
```

Prefer Kubernetes Secrets for the database passwords too:
`--set mongodb.auth.existingSecret=… --set redis.auth.existingSecret=…`.

## Air-gap (CH-29)

Everything (three images + baked model/snapshot) resolves from the Marketplace
ECR; zero external egress. Only the registry needs repointing:

```sh
helm install chariot ./helm/chariot \
  -f ./helm/chariot/values.yaml \
  -f ./helm/chariot/values-airgap.yaml \
  --set global.imageRegistry=<acct>.dkr.ecr.<region>.amazonaws.com \
  --set gateway.existingSecret=chariot-gateway-secret \
  --set mongodb.auth.existingSecret=chariot-mongodb-secret \
  --set redis.auth.existingSecret=chariot-redis-secret
```

## ECS (secondary)

`ecs/chariot-gateway-taskdef.json` is a Fargate task definition template. Replace
the placeholder tokens before `aws ecs register-task-definition`:

| token | meaning |
|---|---|
| `ACCOUNT_ID` | your AWS account id |
| `AWS_REGION` | task region |
| `sha256:REPLACE_WITH_IMAGE_DIGEST` | the immutable digest for the pushed gateway image |

It runs non-root (`user: 1000:1000`), `readonlyRootFilesystem: true`, drops all
Linux capabilities, mounts a writable volume at `/var/lib/chariot`, and pulls
secrets via Secrets Manager ARNs (no baked credentials). MongoDB/Redis run as
sibling ECS services (or managed equivalents); set the gateway's `MONGODB_URI` /
`REDIS_URL` secrets accordingly.

The service-lifecycle hook template
`ecs/chariot-gateway-service-lifecycle-hook.json` wires a Lambda verification
hook into `PRE_SCALE_UP`. The Lambda uses the same digest-pinned image ref and
Notation trust material as the EKS admission policy, packaged under
`ecs/lifecycle-hook/notation/`. If the signature is absent or invalid, the hook
returns `FAILED`, publishes an SNS alert, and the ECS deployment does not
advance.

The ECS task-def defaults to `CHARIOT_LICENSE_PROVIDER=aws-license-manager`
(the AWS-native delivery surface). The boot gate calls License Manager
`CheckoutLicense` (CH-24), so the **task role** (`taskRoleArn`) must grant
`license-manager:CheckoutLicense` and `license-manager:CheckInLicense`; set
`CHARIOT_LM_PRODUCT_SKU` and `CHARIOT_LM_TIER` to the purchased values. On EKS
the same permissions attach to the IRSA role (`serviceAccount.roleArn`). Off
Marketplace, leave `license.provider: offline`.

## Image tags (CH-26)

Images use immutable tags `chariot-vX.Y.Z` (or a digest); **never `latest`**.
Generate the gateway tag from the package version:

```sh
node scripts/release.mjs --emit-image-tag   # -> chariot-v4.0.0
```

The chart **fails the render** if any image is set to `latest` without a digest.

## Invariant mapping

| Invariant | Where |
|---|---|
| CH-24 License Manager / offline default | `license.*` → `templates/configmap.yaml` (CHARIOT_LICENSE_PROVIDER, CHARIOT_AWS_LICENSE_MANAGER, CHARIOT_LM_*) |
| CH-25 no AWS creds; IRSA / task role | `serviceAccount.roleArn` → `templates/serviceaccount.yaml`; ECS `taskRoleArn` |
| CH-26 immutable tags, no `latest` | `*.image.tag/digest`; `chariot.gatewayImage` / subchart image helpers `fail` on `latest` |
| CH-27 embedded vector store | three-image set only (gateway + mongodb + redis); no vector pod |
| CH-28 fail-closed DB creds | `charts/mongodb`, `charts/redis` `secret.yaml` + `chariot.assertStrongSecret`; gateway `existingSecret` required |
| CH-29 self-contained air-gap | all image refs in `values.yaml`; `values-airgap.yaml` registry override |
| CH-30 non-root, least-privilege, writable volume | `podSecurityContext`/`securityContext`; `pvc.yaml` mounted at `EPIC_AI_DIR_OVERRIDE=/var/lib/chariot` |
| CH-54 image seal | `imageVerification.*` renders the Kyverno admission policy, which mutates gateway Pods to digest-pinned refs and verifies the Notary signature; ECS hook template uses the same digest-pinned image ref |

## Validate

```sh
helm lint ./helm/chariot
helm template chariot ./helm/chariot \
  --set global.imageRegistry=<acct>.dkr.ecr.<region>.amazonaws.com \
  --set gateway.existingSecret=s \
  --set mongodb.auth.rootPassword='Str0ng-Pass-9f3a2b' \
  --set redis.auth.password='Str0ng-Pass-9f3a2b'
```
