use color_eyre::eyre::WrapErr;
use color_eyre::eyre::{Result, eyre};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::Service;
use kube::{Api, Client, Error as KubeError};
use tracing::{debug, info, warn};

const DRAGONFLY_NAMESPACE: &str = "dragonfly";
const DRAGONFLY_STATEFULSET: &str = "dragonfly";
const WEBUI_NAMESPACE: &str = "tinkerbell";
const WEBUI_SERVICE: &str = "tinkerbell";
const WEBUI_EXTERNAL_PORT: i32 = 7171; // Tinkerbell HTTP Smee service

/// Checks if the Kubernetes API server is reachable by attempting to get the 'dragonfly' service in the 'dragonfly' namespace.
pub async fn check_kubernetes_connectivity() -> Result<()> {
    debug!(
        "Attempting to connect to Kubernetes API server by checking for 'dragonfly' service in 'dragonfly' namespace..."
    );
    let client = Client::try_default().await.wrap_err(
        "Failed to create Kubernetes client. Is k3s running and KUBECONFIG configured?",
    )?;

    // Get handle for Services in the 'tink' namespace
    let services: Api<Service> = Api::namespaced(client, "tink");

    // Attempt to get the specific service
    match services.get("dragonfly").await {
        Ok(_) => {
            // Service found, connection is definitely working
            debug!(
                "Successfully connected to Kubernetes API server and found 'dragonfly' service in 'tink' namespace."
            );
            Ok(())
        }
        Err(KubeError::Api(ae)) if ae.code == 404 => {
            // Service not found, but the API server responded, so connection is working
            debug!(
                "Successfully connected to Kubernetes API server (service 'dragonfly' not found in 'tink', but API responded)."
            );
            Ok(()) // Treat 404 as success for connectivity check
        }
        Err(e) => {
            // Other errors (network, auth, server error) indicate a connectivity problem
            debug!("Failed to get 'dragonfly' service: {}", e); // Log the actual KubeError
            Err(e).wrap_err("Failed to query Kubernetes API server for 'dragonfly' service. Cluster might be unreachable, unresponsive, or permissions insufficient.")
        }
    }
}

/// Checks the status of the Dragonfly StatefulSet.
/// Returns Ok(true) if ready, Ok(false) if not ready, Err if API call fails.
pub async fn check_dragonfly_statefulset_status() -> Result<bool> {
    debug!(
        "Checking status of StatefulSet '{}/{}'...",
        DRAGONFLY_NAMESPACE, DRAGONFLY_STATEFULSET
    );
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            // If client creation fails, k8s is likely unavailable or not configured.
            warn!(
                "Failed to create Kubernetes client: {}. Assuming StatefulSet is not ready.",
                e
            );
            return Ok(false); // Not an error in checking status, just means k8s isn't there
        }
    };

    let sts: Api<StatefulSet> = Api::namespaced(client, DRAGONFLY_NAMESPACE);

    match sts.get(DRAGONFLY_STATEFULSET).await {
        Ok(stateful_set) => {
            let spec = stateful_set
                .spec
                .ok_or_else(|| eyre!("StatefulSet '{}' has no spec", DRAGONFLY_STATEFULSET))?;
            let status = stateful_set
                .status
                .ok_or_else(|| eyre!("StatefulSet '{}' has no status", DRAGONFLY_STATEFULSET))?;

            let desired_replicas = spec.replicas.unwrap_or(0); // Default to 0 if not specified
            let ready_replicas = status.ready_replicas.unwrap_or(0);

            debug!(
                "StatefulSet '{}/{}': Desired replicas = {}, Ready replicas = {}",
                DRAGONFLY_NAMESPACE, DRAGONFLY_STATEFULSET, desired_replicas, ready_replicas
            );

            // Consider ready if desired > 0 and ready == desired
            if desired_replicas > 0 && ready_replicas == desired_replicas {
                info!(
                    "StatefulSet '{}/{}' is ready.",
                    DRAGONFLY_NAMESPACE, DRAGONFLY_STATEFULSET
                );
                Ok(true)
            } else {
                debug!(
                    "StatefulSet '{}/{}' is not ready (desired={}, ready={}).",
                    DRAGONFLY_NAMESPACE, DRAGONFLY_STATEFULSET, desired_replicas, ready_replicas
                );
                Ok(false)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            debug!(
                "StatefulSet '{}/{}' not found.",
                DRAGONFLY_NAMESPACE, DRAGONFLY_STATEFULSET
            );
            Ok(false) // Not found means not ready
        }
        Err(e) => {
            // Other API errors are actual errors in checking status
            Err(e).wrap_err_with(|| {
                format!(
                    "Failed to get StatefulSet '{}/{}'",
                    DRAGONFLY_NAMESPACE, DRAGONFLY_STATEFULSET
                )
            })
        }
    }
}

/// Attempts to determine the WebUI access address by inspecting the Kubernetes Service.
pub async fn get_webui_address() -> Result<Option<String>> {
    debug!(
        "Attempting to determine WebUI address from Service '{}/{}'...",
        WEBUI_NAMESPACE, WEBUI_SERVICE
    );
    let client = Client::try_default()
        .await
        .wrap_err("Failed to create Kubernetes client")?;

    let services: Api<Service> = Api::namespaced(client, WEBUI_NAMESPACE);
    let service_name = WEBUI_SERVICE;

    match services.get(service_name).await {
        Ok(service) => {
            let spec = service
                .spec
                .ok_or_else(|| eyre!("Service '{}' has no spec", service_name))?;
            let status = service
                .status
                .ok_or_else(|| eyre!("Service '{}' has no status", service_name))?;

            let ports = spec.ports.unwrap_or_default();
            // Find the specific external port we are looking for (e.g., 3000 for tink-stack LB)
            let service_port_info = ports.iter().find(|p| p.port == WEBUI_EXTERNAL_PORT);

            if service_port_info.is_none() {
                warn!(
                    "Could not find external port {} configured for service '{}'",
                    WEBUI_EXTERNAL_PORT, service_name
                );
                return Ok(None); // Cannot construct URL without the correct port mapping
            }
            // We'll use WEBUI_EXTERNAL_PORT for the final URL construction
            let external_port = WEBUI_EXTERNAL_PORT;

            // Check service type and status
            match spec.type_.as_deref() {
                Some("LoadBalancer") => {
                    if let Some(lb_status) = status.load_balancer {
                        if let Some(ingress) = lb_status.ingress {
                            if let Some(ingress_point) = ingress.first() {
                                let address = ingress_point
                                    .ip
                                    .as_deref()
                                    .or(ingress_point.hostname.as_deref());

                                if let Some(addr) = address {
                                    // Use the external port defined for the LB service
                                    let url = format!("http://{}:{}", addr, external_port);
                                    info!("Determined WebUI address from LoadBalancer: {}", url);
                                    return Ok(Some(url));
                                } else {
                                    debug!(
                                        "LoadBalancer ingress exists but has no IP or hostname yet."
                                    );
                                }
                            } else {
                                debug!("LoadBalancer status has no ingress points defined.");
                            }
                        } else {
                            debug!("LoadBalancer status is missing ingress information.");
                        }
                    }
                    warn!(
                        "Service '{}' is LoadBalancer type, but address is not yet available.",
                        service_name
                    );
                    Ok(None) // LoadBalancer IP not ready yet
                }
                Some("NodePort") => {
                    // If the target service was NodePort, find the node port corresponding to our external port
                    if let Some(np) = service_port_info.and_then(|p| p.node_port) {
                        // Cannot easily get Node IP here, so suggest localhost
                        let url = format!("http://localhost:{}", np);
                        info!(
                            "Determined WebUI address from NodePort: {} (using localhost as node IP)",
                            url
                        );
                        Ok(Some(url))
                    } else {
                        warn!(
                            "Service '{}' is NodePort type, but couldn't find nodePort for external port {}",
                            service_name, external_port
                        );
                        Ok(None)
                    }
                }
                Some("ClusterIP") | None => {
                    // ClusterIP is not directly useful for external access in this context
                    warn!(
                        "WebUI Service '{}' is ClusterIP type, cannot determine external address.",
                        service_name
                    );
                    Ok(None)
                }
                Some(other) => {
                    warn!("Service '{}' has unhandled type: {}", service_name, other);
                    Ok(None)
                }
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(
                "WebUI Service '{}' not found in namespace '{}'.",
                service_name, WEBUI_NAMESPACE
            );
            Ok(None) // Service not found
        }
        Err(e) => Err(e).wrap_err_with(|| {
            format!(
                "Failed to get Service '{}' in namespace '{}'",
                service_name, WEBUI_NAMESPACE
            )
        }),
    }
}
