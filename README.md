## Solution Overview and Considerations

### Implementation details

The solution is implemented as a Python script for simplicity and the speed of development.

Due to the requirement of the code being complete with necessary tests, the script is split into the module that can be used in tests, the tests proper, and the wrapper that executes an application instance from the module. In this configuration the solution is supposed to be used in production as a Docker image, but the app module consists of a single file and can be easily merged with the wrapper to be used as a standalone script if needs be.

For simplicity and portability, the script only uses the standard library of Python. In a real life scenario various PyPI modules would have been used, for example Requests to send Slack Webhooks, some libraries for parsing configuration, structured JSON logging, StatsD communication and more advanced testing.

To run the script with the default configuration as per the task specification, you can just launch the wrapper script from the root of the repository (`./cert-checker`), optionally enabling debug output (`LOG_LEVEL=debug`). To see the results of checks against real world certificates you can use the sample file with the external IP addresses provided with tests and override the service specs as necessary:
```sh
INSTANCES_FILE=./tests/integration/addrs.txt SERVICES='amazon.com:443=52.88.0.0/13,google.com:443=142.250.0.0/15' LOG_LEVEL=debug ./cert-checker
```
or, in case of using a Docker image build:
```sh
docker build . -t ghcr.io/sangwa/eco-tha:main
docker run --rm -e INSTANCES_FILE=/app/addrs.txt -e SERVICES='amazon.com:443=52.88.0.0/13,google.com:443=142.250.0.0/15' -e LOG_LEVEL=debug -v "$(pwd)/tests/integration/addrs.txt:/app/addrs.txt:ro" ghcr.io/sangwa/eco-tha:main
```

### Input (IP addresses of instances)

Since neither the input file nor any details on the supposed contents or format of the input file were provided, it assumed to be a text file containing a single IP address per line, with optional empty lines and comment lines that start with `#`. The order of IP addresses in the file assumed to be arbitrary, and not all of them may belong to the target services, so the solution determines which addresses are subject to certificate checks based on provided information about target services.

In a real life scenario, if running in Kubernetes, the script would have used a Kubernetes API client to dynamically determine actual IP addresses of the running instances of a service. (It would also require a Kubernetes Service Account along with proper RBAC permissions to do so.)

### Configuration

For simplicity, no config-parsing library was used and all configurable settings are retrieved from a hard-coded set of environment variables.

#### Input file

The search path of the input file can be specified via the environment variable `INSTANCES_FILE` and defaults to `takehome_ip_addresses.txt` (as per the task specification) in the current working directory. A sample file with a few arbitrary addresses that satisfy the task specification is provided in the root of the repository.

The file is not built into the Docker image at the moment, as the list of target instances is supposed to be more or less dynamic. Therefore if the Docker image is used the proper file should be mounted to the Docker image's working directory (`/app`), optionally with the proper path override specified.

#### Services

The information about services subject to the certificate checks is retrieved from the `SERVICES` environment variable, which is expected to have a format `service:port=cidr,...`. So, for example, for services from the task specification the expected value of the variable is `Europa:4000=10.10.6.0/24,Callisto:8000=10.10.8.0/24`, and this value is hard-coded as default.

#### StatsD

StatsD endpoint is retrieved from the `STATSD_ADDR` environment variable that is expected to have the format of `address:port`. If the port is omitted, the default port `8125` is used. The default value is to `10.10.4.14:8125` as per the task specification. Running the script with the default settings in a non-prepared environment will therefore cause an expected error of reporting the metrics generated during the execution of the script at the very end of the execution.

#### Slack Webhook

The URL of the Slack Webhook can be configured via the environment variable `SLACK_WEBHOOK`. At the moment the example URL provided is configured as the default. Running the script with these default settings will therefore cause expected 404 Not Found errors when trying to post Slack messages.

For simplicity, since no specific requirements were outlined, I decided not to spend time on implementing fancy block-formatting for the Slack messages generated, and the urgency of a Slack message is at the moment only indicated by an emoji prefix.

#### Certificate Validation

Since the task specification does not provide a clear description of the moment when a certificate can be considered `outdated` ("not re-issued"), but mentions the re-issue job runs weekly on Thursdays and the solution script can also be run on schedule, the default maximum age of the certificate is set to 1 week (**7 days**).

This value can be overridden via the `FRESHNESS_DAYS` environment variable. The expiration threshold can also be overridden via the `EXPIRATION_DAYS` variable (the default is **30 days** as per the task specification).

All certificates are automatically validated against the certificate trust bundle of the host OS. At the moment this is non-configurable, but of course the script can be modified to support that, or alternatively the trust chain of the service certificates can be added to the trust bundle of the target host or the Docker image.

Since the standard library of Python enforces SNI negotiation on TLS connections by default, it requires the SNI hostname to be set, and it is set automatically to the name of the service as specified in the configuration settings (e.g. `Callisto`). This may have implications, depending on how the target services are actually configured, and whether they support SNI. An incorrect certificate may be produced if a differnt SNI value is expected by the service. Another option could be using the target IP address instead, but I consider this less reliable as certificates of public services rarely contain fixed IP addresses in SANs and therefore less likely to be produced if not set as default. Anyways, since the task specification is not clear on this matter, this is the current choice of implementation. In a real life scenario some FQDNs are likely to be used, like public domains or Kubernetes service discovery domains, rather than arbitrary service names like provided in the task specification, and in case of Kubernetes the management of certificates would likely be automated and offloaded to some service mesh solution or something like `cert-manager` or Hashicorp Vault.

Considering the above, the code also performs the SAN validation by default, making sure the SNI domain is present in the certificate's SAN list (or the CN field). This setting is configurable by the boolean environment variable `CHECK_SAN`.

### Tests

The task specification states that the solution should be a "production ready code complete with all necessary tests". However no specific acceptance criteria or expected coverage is mentioned.

This solution provides a few very basic tests and the code is organized to be easily testable. Without the requirement of tests the basic functionality required could be implemented as a single page script in under one hour. On the other hand I don't really see the point to provide any extensive test coverage, since writing unit tests for every function and devising the end to end tests with necessary infrastructure would have probably taken two to three times more time than already spend on this solution, and honestly I don't think this is really in the scope. More details on testing are provided in the section on the Follow Up Questions below.

## Follow Up Questions

### How would you ensure the script itself is running correctly?

The simplest way is to control the presence of metric datapoints sent to StatsD. If the script fails to run at some point and/or fails to report metrics to StatsD, the age of the last reported datapoints of the script's metrics will increase. An alert can be set for that or for the count of metric datapoints in the recent sliding window (like the last 36 hours).

If the script is run as a Kubernetes (Cron)Job or some other containerized workload (e.g. in ECS or as a Lambda), respective metrics could also be collected and the alerts set on the occurrences of failed runs.

Finally, if the script is executed as a cron job on an EC2 instance, error output from the script can be routed via the local mail subsystem to a public email list (e.g. a Google Group) that is monitored by responsible persons, or optionally re-routed to an alerting system.

### How would you dockerize a test environment?

As mentioned above, the solution does not come with a full-fledged test suite, and the final outcome would depend on the target environment (bare EC2? EKS? ECS/Lambda? etc.) and other requirements.

One way to organize a complete end-to-end test would be creating a `docker-compose` stack that contains:

* Two additional docker networks with different IPAM settings, to emulate the real subnets. (This is not always possible due to the docker host settings. As an alternative, since the `localhost` interface is usually configured with a `/8` netmask, you can bind workloads to a wide range of localhost addresses like `127.10.0.1`, `127.0.100.200`, etc, and configure "virtual" subnets based on that, like `127.10.0.0/24`, etc.)
* A containerized StatsD server instance.
* A few containers of mock TLS servers to act as service instances, launched in respective networks. The server certificates can be auto-generated on the startup.
* Some mock HTTP server to receive requests for the Slack webhooks endpoint.
* The solution image proper, supplied with necessary configuration overrides and running e2e test suites against this mock configuration.

The stack can be executed in a CI pipeline.

### How could you deploy this on an AWS EC2 instance using terraform?

If the goal is to use a "bare" EC2 instance (like the jump host mentioned in the task specification), the proper way would be setting up EC2 instance metadata in the settings of the instance proper or its launch template/ASG. The metadata should contain a script that sets up a regular cron job (daily or weekly on Fridays or on Thursdays after the certificate re-issue job, depending on the configuration and requirements) as well as make sure the script is present on the machine. The latter can be done by pulling a Docker image from an ECR repository or copying it from an S3 bucket, where it is supposed to be placed by a CI pipeline in the both cases. (The IAM role of the EC2 instance should be also granted proper permissions to access ECR/S3 in this case.)

Terraform can also be used to set up necessary infrastructure to run this as an AWS-native job, e.g. an ECS task or a Lambda triggered by an EventBridge schedule rule.

More common scenario is using a Kubernetes CronJob, and in this case Kubernetes-native tools (Helm, GitOps controllers with Kustomize YAML manifests, etc.) are usually employed rather than Terraform. CronJobs come with some caveats though (e.g. you need to monitor and timely address execution failures lest the threshold of failures is exceeded and the CronJob is suspended).

### How would you configure this script to run every `x` days assuming it was being executed within the virtual network?

Most of the options have already been mentioned above. To summarize:
* A classic cron job on an EC2 instance, running the script directly or as a transient Docker container.
* An ECS task or a Lambda triggered by an EventBridge scheduled event.
* A Kubernetes Job, triggered by a Kubernetes CronJob or any external means (like a scheduled CI pipeline).
