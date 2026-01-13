use anyhow::{anyhow, Result};
use kube::{
    api::{Api, PostParams, PatchParams, Patch},
    Client, Error as KubeError, core::DynamicObject,
};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tracing::{error, info, warn};
use dragonfly_common::models::Machine;
use std::str::FromStr;

// Define a static Kubernetes client
static KUBE_CLIENT: OnceCell<Client> = OnceCell::const_new();

// Tinkerbell namespace constant
const TINKERBELL_NAMESPACE: &str = "tinkerbell";

// Initialize the Kubernetes client using KUBECONFIG
pub async fn init() -> Result<()> {
    // Expand the tilde in KUBECONFIG if present
    if let Ok(kubeconfig) = std::env::var("KUBECONFIG") {
        if kubeconfig.starts_with('~') {
            // Replace tilde with home directory
            if let Ok(home) = std::env::var("HOME") {
                let expanded_path = kubeconfig.replacen('~', &home, 1);
                // SAFETY: Single-threaded initialization before spawning async tasks
                unsafe { std::env::set_var("KUBECONFIG", &expanded_path); }
                info!("Expanded KUBECONFIG path: {}", expanded_path);
            }
        }
    }

    // Create a new client using the current environment (KUBECONFIG)
    let client = Client::try_default().await
        .map_err(|e| anyhow!("Failed to create Kubernetes client: {}", e))?;

    // Test the client to ensure it can connect to the cluster
    client
        .apiserver_version()
        .await
        .map_err(|e| anyhow!("Failed to connect to Kubernetes API server: {}", e))?;

    // Set the global client
    if let Err(_) = KUBE_CLIENT.set(client) {
        return Err(anyhow!("Failed to set global Kubernetes client"));
    }

    info!("Kubernetes client initialized successfully");
    Ok(())
}

// Get the Kubernetes client
pub async fn get_client() -> Result<&'static Client> {
    if KUBE_CLIENT.get().is_none() {
        info!("Kubernetes client not initialized, initializing now");

        // Expand the tilde in KUBECONFIG if present
        if let Ok(kubeconfig) = std::env::var("KUBECONFIG") {
            if kubeconfig.starts_with('~') {
                // Replace tilde with home directory
                if let Ok(home) = std::env::var("HOME") {
                    let expanded_path = kubeconfig.replacen('~', &home, 1);
                    // SAFETY: Single-threaded initialization before spawning async tasks
                    unsafe { std::env::set_var("KUBECONFIG", &expanded_path); }
                    info!("Expanded KUBECONFIG path: {}", expanded_path);
                }
            }
        }

        // Create a new client using the current environment (KUBECONFIG)
        let client = match Client::try_default().await {
            Ok(client) => client,
            Err(e) => {
                return Err(anyhow!("Failed to create Kubernetes client: {}", e));
            }
        };

        // Test the client to ensure it can connect to the cluster
        if let Err(e) = client.apiserver_version().await {
            return Err(anyhow!("Failed to connect to Kubernetes API server: {}", e));
        }

        // Set the global client
        if let Err(_) = KUBE_CLIENT.set(client) {
            return Err(anyhow!("Failed to set global Kubernetes client"));
        }

        info!("Kubernetes client initialized successfully");
    }

    KUBE_CLIENT.get().ok_or_else(|| anyhow!("Kubernetes client initialization failed"))
}

// Define the Hardware Custom Resource using serde
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Hardware {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: HardwareSpec,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Metadata {
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HardwareMetadata {
    instance: Instance,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Instance {
    id: String,
    hostname: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HardwareSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<HardwareMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disks: Option<Vec<DiskSpec>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interfaces: Option<Vec<InterfaceSpec>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DiskSpec {
    device: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct InterfaceSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    dhcp: Option<DHCPSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    netboot: Option<NetbootSpec>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DHCPSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<IPSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_time: Option<u32>,
    mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uefi: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IPSpec {
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    netmask: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NetbootSpec {
    #[serde(rename = "allowPXE")]
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_pxe: Option<bool>,
    #[serde(rename = "allowWorkflow")]
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_workflow: Option<bool>,
}

// Register a machine with Tinkerbell
pub async fn register_machine(machine: &Machine) -> Result<()> {
    // Get the Kubernetes client
    let client = match get_client().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping Tinkerbell registration: {}", e);
            return Ok(());
        }
    };

    // Create a unique name for the hardware resource based on MAC address
    let resource_name = format!("machine-{}", machine.mac_address.replace(":", "-"));

    // --- Determine Hostname (Final Complete Rewrite) ---
    // Start with the fallback/default (MAC-based name)
    let mut resolved_hostname = resource_name.clone();

    // Try hostname if set (Fallback 2)
    if let Some(hostname) = &machine.hostname {
        resolved_hostname = hostname.clone();
    }

    // Attempt reverse DNS lookup if we have a valid IP
    if let Ok(ip_addr) = std::net::IpAddr::from_str(&machine.ip_address) {
        // Create resolver - note: this function returns the resolver itself, not a Result
        let resolver = hickory_resolver::AsyncResolver::tokio(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::config::ResolverOpts::default()
        );

        // Try reverse lookup
        if let Ok(response) = resolver.reverse_lookup(ip_addr).await {
            if let Some(name) = response.iter().next() {
                let rdns_name = name.to_utf8().trim_end_matches('.').to_string();
                info!("Using hostname from reverse DNS lookup for {}: {}", ip_addr, rdns_name);
                resolved_hostname = rdns_name;
            } else {
                warn!("Reverse DNS lookup returned empty result for {}", ip_addr);
            }
        } else {
            warn!("Reverse DNS lookup failed for {}", ip_addr);
        }
    } else {
        warn!("Invalid IP address format for DNS lookup: '{}'", machine.ip_address);
    }

    // --- End Determine Hostname ---

    register_machine_internal(client, machine, &resource_name, &resolved_hostname).await
}

// Internal function to handle the actual machine registration with Tinkerbell
async fn register_machine_internal(
    client: &'static Client,
    machine: &Machine,
    resource_name: &str,
    resolved_hostname: &str,
) -> Result<()> {
    let memorable_name = machine.memorable_name.clone().unwrap_or_else(|| resource_name.to_string());

    info!("Registering machine {} with Tinkerbell", resource_name);

    // Create the Hardware resource, focusing only on the specific fields we need to set
    // to reduce conflicts with other field managers
    let hardware = Hardware {
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        kind: "Hardware".to_string(),
        metadata: Metadata {
            name: resource_name.to_string(),
            namespace: TINKERBELL_NAMESPACE.to_string(),
            labels: None,
        },
        spec: HardwareSpec {
            metadata: Some(HardwareMetadata {
                instance: Instance {
                    id: memorable_name,
                    hostname: resolved_hostname.to_string(),
                },
            }),
            disks: Some(machine.disks.iter().map(|disk| DiskSpec {
                device: disk.device.clone(),
            }).collect()),
            interfaces: Some(vec![InterfaceSpec {
                dhcp: Some(DHCPSpec {
                    arch: Some("x86_64".to_string()),
                    hostname: Some(resolved_hostname.to_string()),
                    ip: Some(IPSpec {
                        address: machine.ip_address.clone(),
                        gateway: None,
                        netmask: None,
                    }),
                    lease_time: Some(86400),
                    mac: machine.mac_address.clone(),
                    name_servers: Some(machine.nameservers.clone()),
                    uefi: Some(true),
                }),
                netboot: Some(NetbootSpec {
                    allow_pxe: Some(true),
                    allow_workflow: Some(true),
                }),
            }]),
        },
    };

    // Convert the Hardware resource to JSON
    let hardware_json = serde_json::to_value(&hardware)?;

    // Create the ApiResource for the Hardware CRD
    let api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Hardware".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "hardware".to_string(),
    };

    info!("Using Kubernetes API Resource: group={}, version={}, kind={}, plural={}",
          api_resource.group, api_resource.version, api_resource.kind, api_resource.plural);

    // Create a dynamic API to interact with the Hardware custom resource
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), TINKERBELL_NAMESPACE, &api_resource);

    // Create a DynamicObject from our hardware_json
    let mut dynamic_obj = DynamicObject {
        metadata: kube::core::ObjectMeta {
            name: Some(resource_name.to_string()),
            namespace: Some(TINKERBELL_NAMESPACE.to_string()),
            ..Default::default()
        },
        types: Some(kube::core::TypeMeta {
            api_version: "tinkerbell.org/v1alpha1".to_string(),
            kind: "Hardware".to_string(),
        }),
        data: hardware_json,
    };

    // Check if the hardware resource already exists
    match api.get(&resource_name).await {
        Ok(_existing) => {
            info!("Found existing Hardware resource in Tinkerbell: {}", resource_name);

            // Use JSON merge patch instead of server-side apply
            let patch_params = PatchParams::default();

            info!("Applying update via JSON merge patch");

            // Use JSON merge patch to update the resource
            match api.patch(&resource_name, &patch_params, &Patch::Merge(dynamic_obj)).await {
                Ok(patched) => {
                    info!(
                        "Updated Hardware resource in Tinkerbell: {} (resourceVersion: {:?})",
                        resource_name,
                        patched.metadata.resource_version
                    );
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to update Hardware resource in Tinkerbell: {}", e);
                    Err(anyhow!("Failed to update Hardware resource: {}", e))
                }
            }
        },
        Err(KubeError::Api(ae)) if ae.code == 404 => {
            info!("No existing Hardware resource found, creating new one: {}", resource_name);

            // For creation, ensure we have a clean metadata without resourceVersion
            dynamic_obj.metadata = kube::core::ObjectMeta {
                name: Some(resource_name.to_string()),
                namespace: Some(TINKERBELL_NAMESPACE.to_string()),
                ..Default::default()
            };

            // Create a new hardware resource
            match api.create(&PostParams::default(), &dynamic_obj).await {
                Ok(created) => {
                    info!(
                        "Created new Hardware resource in Tinkerbell: {} (initial resourceVersion: {:?})",
                        resource_name,
                        created.metadata.resource_version
                    );
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to create Hardware resource in Tinkerbell: {}", e);
                    Err(anyhow!("Failed to create Hardware resource: {}", e))
                }
            }
        },
        Err(e) => {
            error!("Error checking Hardware resource in Tinkerbell: {}", e);
            Err(anyhow!("Error checking Hardware resource: {}", e))
        }
    }
}

// Add this function to delete hardware resources
pub async fn delete_hardware(mac_address: &str) -> Result<()> {
    // Get the Kubernetes client
    let client = match get_client().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping Tinkerbell deletion: {}", e);
            return Err(anyhow!("Kubernetes client not initialized: {}", e));
        }
    };

    let resource_name = mac_address.to_lowercase();
    info!("Deleting hardware resource from Tinkerbell: {}", resource_name);

    // Create the ApiResource for the Hardware CRD
    let api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Hardware".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "hardware".to_string(),
    };

    // Create a dynamic API to interact with the Hardware custom resource
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), TINKERBELL_NAMESPACE, &api_resource);

    // Delete the hardware resource
    let hardware_result = api.delete(&resource_name, &kube::api::DeleteParams::default()).await;

    // Also delete any associated workflow
    let workflow_name = format!("os-install-{}", mac_address.replace(":", "-"));
    info!("Deleting workflow resource from Tinkerbell: {}", workflow_name);

    // Create the ApiResource for the Workflow CRD
    let workflow_api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Workflow".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "workflows".to_string(),
    };

    // Create a dynamic API to interact with the Workflow custom resource
    let workflow_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), TINKERBELL_NAMESPACE, &workflow_api_resource);

    // Delete the workflow resource
    let workflow_result = workflow_api.delete(&workflow_name, &kube::api::DeleteParams::default()).await;

    // Handle results
    match (hardware_result, workflow_result) {
        (Ok(_), Ok(_)) => {
            info!("Successfully deleted hardware and workflow resources");
            Ok(())
        },
        (Ok(_), Err(KubeError::Api(ae))) if ae.code == 404 => {
            info!("Successfully deleted hardware resource, workflow was not found");
            Ok(())
        },
        (Err(KubeError::Api(ae)), Ok(_)) if ae.code == 404 => {
            info!("Hardware resource not found, but successfully deleted workflow");
            Ok(())
        },
        (Err(KubeError::Api(ae1)), Err(KubeError::Api(ae2))) if ae1.code == 404 && ae2.code == 404 => {
            info!("Neither hardware nor workflow resources were found (already deleted)");
            Ok(())
        },
        (Err(e), _) => {
            error!("Failed to delete hardware resource from Tinkerbell: {}", e);
            Err(anyhow!("Failed to delete hardware resource: {}", e))
        },
        (_, Err(e)) => {
            error!("Failed to delete workflow resource from Tinkerbell: {}", e);
            Err(anyhow!("Failed to delete workflow resource: {}", e))
        }
    }
}

// Create a Workflow for OS installation
pub async fn create_workflow(machine: &Machine, _os_choice: &str) -> Result<()> {
    // Get the Kubernetes client
    let client = match get_client().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping Tinkerbell workflow creation: {}", e);
            return Ok(());
        }
    };

    // Use MAC address without colons as part of the workflow name
    let resource_name = format!("os-install-{}", machine.mac_address.replace(":", "-"));

    // Hardware reference name (matches what we create in register_machine)
    let hardware_ref = format!("machine-{}", machine.mac_address.replace(":", "-"));

    info!("Creating workflow {} for machine {}", resource_name, machine.id);

    // Map OS choice to template reference
    let template_ref = match machine.os_choice.as_ref() {
        Some(os) if os == "ubuntu-2204" => "ubuntu-2204",
        Some(os) if os == "ubuntu-2404" => "ubuntu-2404",
        Some(os) if os == "debian-12" => "debian-12",
        Some(os) if os == "proxmox" => "proxmox",
        Some(os) if os == "talos" => "talos",
        Some(os) => os,
        None => "ubuntu-2204", // Default if no OS choice is specified
    };

    // First check if the Template exists
    let template_api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Template".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "templates".to_string(),
    };

    let template_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), TINKERBELL_NAMESPACE, &template_api_resource);

    match template_api.get(template_ref).await {
        Ok(_) => {
            info!("Template '{}' found in Tinkerbell, proceeding with workflow creation", template_ref);
        },
        Err(KubeError::Api(ae)) if ae.code == 404 => {
            error!("Template '{}' not found in Tinkerbell! Workflow creation will fail. Please create this template first.", template_ref);
            return Err(anyhow!("Template '{}' not found in Tinkerbell namespace. Workflow creation aborted.", template_ref));
        },
        Err(e) => {
            warn!("Error checking for template '{}': {}. Proceeding with workflow creation anyway.", template_ref, e);
        }
    }

    // Create the Workflow resource
    let workflow_json = serde_json::json!({
        "apiVersion": "tinkerbell.org/v1alpha1",
        "kind": "Workflow",
        "metadata": {
            "name": resource_name,
            "namespace": TINKERBELL_NAMESPACE
        },
        "spec": {
            "templateRef": template_ref,
            "hardwareRef": hardware_ref,
            "hardwareMap": {
                "device_1": machine.mac_address
            }
        }
    });

    // Create the ApiResource for the Workflow CRD
    let api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Workflow".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "workflows".to_string(),
    };

    info!("Using Kubernetes API Resource for Workflow: group={}, version={}, kind={}, plural={}",
          api_resource.group, api_resource.version, api_resource.kind, api_resource.plural);

    // Create a dynamic API to interact with the Workflow custom resource
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), TINKERBELL_NAMESPACE, &api_resource);

    // Create a DynamicObject from our workflow_json
    let dynamic_obj = DynamicObject {
        metadata: kube::core::ObjectMeta {
            name: Some(resource_name.clone()),
            namespace: Some(TINKERBELL_NAMESPACE.to_string()),
            ..Default::default()
        },
        types: Some(kube::core::TypeMeta {
            api_version: "tinkerbell.org/v1alpha1".to_string(),
            kind: "Workflow".to_string(),
        }),
        data: workflow_json,
    };

    // Check if the workflow resource already exists
    match api.get(&resource_name).await {
        Ok(_existing) => {
            info!("Found existing Workflow resource in Tinkerbell: {}", resource_name);

            // Use JSON merge patch to update the resource
            let patch_params = PatchParams::default();
            match api.patch(&resource_name, &patch_params, &Patch::Merge(&dynamic_obj)).await {
                Ok(patched) => {
                    info!(
                        "Updated Workflow resource in Tinkerbell: {} (resourceVersion: {:?})",
                        resource_name,
                        patched.metadata.resource_version
                    );
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to update Workflow resource in Tinkerbell: {}", e);
                    Err(anyhow!("Failed to update Workflow resource: {}", e))
                }
            }
        },
        Err(KubeError::Api(ae)) if ae.code == 404 => {
            info!("No existing Workflow resource found, creating new one: {}", resource_name);

            // Create a new workflow resource
            match api.create(&PostParams::default(), &dynamic_obj).await {
                Ok(created) => {
                    info!(
                        "Created new Workflow resource in Tinkerbell: {} (initial resourceVersion: {:?})",
                        resource_name,
                        created.metadata.resource_version
                    );
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to create Workflow resource in Tinkerbell: {}", e);
                    Err(anyhow!("Failed to create Workflow resource: {}", e))
                }
            }
        },
        Err(e) => {
            error!("Error checking Workflow resource in Tinkerbell: {}", e);
            Err(anyhow!("Error checking Workflow resource: {}", e))
        }
    }
}

// Define structs for the workflow status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub name: String,
    pub status: String,
    pub started_at: String,
    pub duration: u64,
    pub reported_duration: u64,
    pub estimated_duration: u64,
    pub progress: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInfo {
    pub state: String,
    pub current_action: Option<String>,
    pub progress: u8,
    pub tasks: Vec<TaskInfo>,
    pub estimated_completion: Option<String>,
    pub template_name: String,
}

// Create a static map to store historical timing data
use std::collections::HashMap;
use std::sync::RwLock;
use once_cell::sync::Lazy;

// Historical timing map indexed by template name, then action name
// This allows us to store different timing profiles for different OS templates
static HISTORICAL_TIMINGS: Lazy<RwLock<HashMap<String, HashMap<String, Vec<u64>>>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

// Calculate average time for a specific action based on historical data for a specific template
fn get_avg_time_for_action(template_name: &str, action_name: &str) -> Option<u64> {
    if let Ok(timings) = HISTORICAL_TIMINGS.read() {
        // Try to get specific template/action timing
        if let Some(template_timings) = timings.get(template_name) {
            if let Some(durations) = template_timings.get(action_name) {
                if !durations.is_empty() {
                    let sum: u64 = durations.iter().sum();
                    let avg = sum / durations.len() as u64;
                    return Some(avg);
                }
            }

            // If no data for this specific template/action, try to use data from any template as fallback
            for (other_template, template_data) in timings.iter() {
                if let Some(durations) = template_data.get(action_name) {
                    if !durations.is_empty() {
                        let sum: u64 = durations.iter().sum();
                        let avg = sum / durations.len() as u64;
                        info!("Using fallback timing from {}/{}: avg={}s from {} samples",
                              other_template, action_name, avg, durations.len());
                        return Some(avg);
                    }
                }
            }
        }
    }

    None
}

// Load previously saved timing data from the database
pub async fn load_historical_timings() -> Result<()> {
    info!("Loading historical timing data from database");

    // Get timing data from database
    let timings = match crate::db::load_template_timings().await {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to load template timings from database: {}", e);
            return Ok(()); // Continue without historical data
        }
    };

    // Update in-memory timing data
    if let Ok(mut timing_map) = HISTORICAL_TIMINGS.write() {
        for timing in timings {
            let template_timings = timing_map
                .entry(timing.template_name)
                .or_insert_with(HashMap::new);

            template_timings.insert(timing.action_name, timing.durations);
        }
    }

    info!("Loaded historical timing data for {} templates",
        HISTORICAL_TIMINGS.read().map(|map| map.len()).unwrap_or(0));

    Ok(())
}

// Store timing information after a successful workflow
fn store_timing_info(template_name: &str, tasks: &[TaskInfo]) {
    const MAX_TIMING_HISTORY: usize = 50; // Keep only the last 50 runs of timing data

    info!("Attempting to store timing data for {} tasks in template '{}'", tasks.len(), template_name);

    if let Ok(mut timings) = HISTORICAL_TIMINGS.write() {
        // Get or create the template's timing map
        let template_timings = timings
            .entry(template_name.to_string())
            .or_insert_with(HashMap::new);

        // Add each task's timing data and save to database
        for task in tasks {
            // Skip tasks with zero duration as they don't provide useful timing data
            if task.reported_duration == 0 {
                warn!("Task '{}' has zero reported_duration, skipping", task.name);
                continue;
            }

            info!("Saving timing data: {}:{} = {}s", template_name, task.name, task.reported_duration);

            let durations = template_timings
                .entry(task.name.clone())
                .or_insert_with(Vec::new);

            // Only store reported_duration (actual time taken)
            durations.push(task.reported_duration);

            // Trim the list to keep only the most recent MAX_TIMING_HISTORY entries
            if durations.len() > MAX_TIMING_HISTORY {
                // Remove the oldest entries (those at the start of the vector)
                *durations = durations.iter().skip(durations.len() - MAX_TIMING_HISTORY).cloned().collect();
            }

            // Save to database asynchronously
            tokio::spawn(save_timing_to_db(
                template_name.to_string(),
                task.name.clone(),
                durations.clone()
            ));
        }
    } else {
        error!("Failed to acquire write lock for storing timing data");
    }
}

// Save timing data to database asynchronously
async fn save_timing_to_db(template_name: String, action_name: String, durations: Vec<u64>) {
    if let Err(e) = crate::db::save_template_timing(&template_name, &action_name, &durations).await {
        warn!("Failed to save timing data for {}/{} to database: {}", template_name, action_name, e);
    }
}

// Get workflow information from Kubernetes for a specific machine
pub async fn get_workflow_info(machine: &Machine) -> Result<Option<WorkflowInfo>> {
    // First check if we have a recently completed workflow
    if let Ok(Some((workflow_info, _completed_at))) = crate::db::get_completed_workflow(&machine.id).await {
        return Ok(Some(workflow_info));
    }

    // If no completed workflow found, check for active workflow
    // Get the Kubernetes client
    let client = match get_client().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping workflow status check: {}", e);
            return Ok(None);
        }
    };

    // Create the workflow resource name based on the MAC address
    let workflow_name = format!("os-install-{}", machine.mac_address.replace(":", "-"));

    // Create the ApiResource for the Workflow CRD
    let api_resource = kube::core::ApiResource {
        group: "tinkerbell.org".to_string(),
        version: "v1alpha1".to_string(),
        kind: "Workflow".to_string(),
        api_version: "tinkerbell.org/v1alpha1".to_string(),
        plural: "workflows".to_string(),
    };

    // Create a dynamic API to interact with the Workflow custom resource
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), TINKERBELL_NAMESPACE, &api_resource);

    // Try to get the workflow
    match api.get(&workflow_name).await {
        Ok(workflow) => {
            // Extract template reference from the workflow spec for time tracking
            let template_ref = workflow.data.get("spec")
                .and_then(|spec| spec.get("templateRef"))
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            // Process workflow status from the DynamicObject
            if let Some(status) = workflow.data.get("status") {
                let state = status.get("state").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
                let current_action = status.get("currentAction").and_then(|a| a.as_str()).map(|s| s.to_string());

                // HACK: If a machine is stuck in STATE_RUNNING with current action "kexec to boot OS",
                // it has likely successfully booted the OS. Mark it as Ready and delete the workflow.
                // STATE_FAILED is always considered a failure regardless of the current action.
                if (state == "STATE_RUNNING" && current_action.as_deref() == Some("kexec to boot OS")) ||
                   is_workflow_timed_out(status, current_action.as_deref()) {
                    info!("HACK: Detected machine {} in STATE_RUNNING for 'kexec to boot OS' or timed out. Marking as Ready and deleting workflow.",
                          machine.id);

                    // Extract tasks to get timing data before marking as complete
                    let mut tasks = Vec::new();
                    if let Some(task_array) = status.get("tasks") {
                        if let Some(task_array) = task_array.as_array() {
                            for task_obj in task_array {
                                if let Some(actions) = task_obj.get("actions") {
                                    if let Some(actions) = actions.as_array() {
                                        for action in actions {
                                            let name = action.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
                                            let status = action.get("status").and_then(|s| s.as_str()).unwrap_or("UNKNOWN").to_string();
                                            let started_at = action.get("startedAt").and_then(|s| s.as_str()).unwrap_or("").to_string();

                                            // Only collect completed tasks for timing data
                                            if status == "STATE_SUCCESS" {
                                                let reported_seconds = action.get("seconds").and_then(|s| s.as_i64()).unwrap_or(0) as u64;
                                                let estimated_seconds = get_avg_time_for_action(template_ref, &name).unwrap_or(0);

                                                tasks.push(TaskInfo {
                                                    name,
                                                    status,
                                                    started_at,
                                                    duration: reported_seconds,
                                                    reported_duration: reported_seconds,
                                                    estimated_duration: estimated_seconds,
                                                    progress: 0,
                                                });
                                            }
                                            // Also capture the kexec action even if it's not officially completed
                                            else if status == "STATE_RUNNING" && name == "kexec to boot OS" {
                                                let reported_seconds = action.get("seconds").and_then(|s| s.as_i64()).unwrap_or(0) as u64;
                                                let estimated_seconds = get_avg_time_for_action(template_ref, &name).unwrap_or(0);

                                                // Add the kexec task but mark it as successful since we're considering the workflow complete
                                                tasks.push(TaskInfo {
                                                    name,
                                                    status: "STATE_SUCCESS".to_string(), // Override status to SUCCESS
                                                    started_at,
                                                    duration: reported_seconds,
                                                    reported_duration: reported_seconds,
                                                    estimated_duration: estimated_seconds,
                                                    progress: 0,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Store timing data for completed tasks
                    if !tasks.is_empty() {
                        info!("Storing timing data for {} completed tasks from kexec-detected workflow", tasks.len());
                        store_timing_info(template_ref, &tasks);
                    }

                    // Create a special WorkflowInfo to indicate this was handled by the hack
                    let workflow_info = WorkflowInfo {
                        state: "STATE_SUCCESS".to_string(),
                        current_action: Some("Completed via kexec detection".to_string()),
                        progress: 100,
                        tasks,  // Use the extracted tasks instead of empty vector
                        estimated_completion: Some("Deployment complete".to_string()),
                        template_name: template_ref.to_string(),
                    };

                    // Store the completed workflow info
                    if let Err(e) = crate::db::store_completed_workflow(&machine.id, &workflow_info).await {
                        warn!("Failed to store completed workflow info: {}", e);
                    } else {
                        info!("Successfully stored completed workflow info for {}", machine.id);
                    }

                    // Send a machine_updated event to refresh the UI
                    if let Some(event_manager) = get_event_manager() {
                        info!("Sending machine_updated event after kexec detection success for: {}", machine.id);
                        // TODO: Handle error
                        event_manager.send(format!("machine_updated:{}", machine.id));
                    }

                    // Add a short delay to ensure the UI has time to update and show the completion message
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    // Update machine status to Ready AFTER UI has chance to show completion message
                    if let Err(e) = update_machine_status_on_success(machine).await {
                        warn!("Failed to update machine status after kexec detection: {}", e);
                    } else {
                        info!("Successfully marked machine {} as Ready", machine.id);
                    }

                    // Delete the workflow
                    let delete_params = kube::api::DeleteParams::default();
                    match api.delete(&workflow_name, &delete_params).await {
                        Ok(_) => info!("Successfully deleted workflow {}", workflow_name),
                        Err(e) => warn!("Failed to delete workflow {}: {}", workflow_name, e),
                    }

                    return Ok(Some(workflow_info));
                }

                // Extract all tasks from the workflow
                let mut tasks = Vec::new();
                let mut total_seconds = 0;
                let mut completed_seconds = 0;
                let mut running_task_info = None;
                let mut running_task_started_at = None;

                if let Some(task_array) = status.get("tasks") {
                    if let Some(task_array) = task_array.as_array() {
                        for task_obj in task_array {
                            if let Some(actions) = task_obj.get("actions") {
                                if let Some(actions) = actions.as_array() {
                                    for action in actions {
                                        let name = action.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
                                        let status = action.get("status").and_then(|s| s.as_str()).unwrap_or("UNKNOWN").to_string();
                                        let started_at = action.get("startedAt").and_then(|s| s.as_str()).unwrap_or("").to_string();

                                        // Get actual duration from completed actions or estimate from template history
                                        let reported_seconds = action.get("seconds").and_then(|s| s.as_i64()).unwrap_or(0) as u64;

                                        // Only rely on historical timing data or reported seconds
                                        let estimated_seconds = get_avg_time_for_action(template_ref, &name);

                                        // Use the reported seconds for completed tasks, or estimated seconds if available
                                        let seconds = if status == "STATE_SUCCESS" {
                                            reported_seconds  // Use actual time for completed tasks
                                        } else if let Some(est) = estimated_seconds {
                                            est // Use estimated time from history
                                        } else if reported_seconds > 0 {
                                            reported_seconds // Fall back to reported seconds if non-zero
                                        } else {
                                            // We have no data at all
                                            0 // Can't make any assumptions
                                        };

                                        total_seconds += seconds;

                                        if status == "STATE_SUCCESS" {
                                            completed_seconds += seconds;
                                        } else if status == "STATE_RUNNING" {
                                            // Parse started_at for later use
                                            let started_at_parsed = if !started_at.is_empty() {
                                                chrono::DateTime::parse_from_rfc3339(&started_at)
                                                    .ok()
                                                    .map(|dt| dt.with_timezone(&chrono::Utc))
                                            } else {
                                                None
                                            };

                                            // Store the current running task info for later progress calculation
                                            running_task_info = Some((name.clone(), seconds));
                                            running_task_started_at = started_at_parsed;
                                        }

                                        // Add tasks to the array
                                        let _current_date = chrono::Utc::now();
                                        tasks.push(TaskInfo {
                                            name: name.clone(),
                                            status: status.clone(),
                                            started_at: started_at.clone(),
                                            duration: seconds,
                                            reported_duration: reported_seconds,
                                            estimated_duration: estimated_seconds.unwrap_or(0),
                                            progress: 0, // Initialize to 0, will calculate after all tasks are collected
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Calculate progress for all tasks based on elapsed time
                let current_time = chrono::Utc::now();
                for (i, task) in tasks.iter_mut().enumerate() {
                    if task.status == "STATE_RUNNING" && !task.started_at.is_empty() {
                        if let Ok(started_at) = chrono::DateTime::parse_from_rfc3339(&task.started_at) {
                            let started_at_utc = started_at.with_timezone(&chrono::Utc);
                            let elapsed_seconds = current_time.signed_duration_since(started_at_utc).num_seconds().max(0) as u64;

                            if task.estimated_duration > 0 {
                                // Calculate raw progress as elapsed/estimated, capped at 100%
                                let progress_pct = (elapsed_seconds as f64 / task.estimated_duration as f64 * 100.0).min(100.0);

                                // Update the task progress
                                task.progress = progress_pct as u8;

                                // Log the progress calculation
                                info!("Task '{}'(#{}) progress updated: {}% ({}/{}s elapsed)",
                                    task.name, i, task.progress, elapsed_seconds, task.estimated_duration);
                            }
                        }
                    } else if task.status == "STATE_SUCCESS" {
                        task.progress = 100;
                    }
                }

                // Calculate fluid progress percentage using timing data
                let progress = if total_seconds > 0 {
                    // Start with progress from completed tasks
                    let mut time_based_progress = completed_seconds as f64 / total_seconds as f64 * 100.0;

                    // If there's a running task, use its task-specific progress for the overall calculation
                    if let (Some((running_task_name, expected_duration)), Some(started_at)) = (&running_task_info, &running_task_started_at) {
                        // Find the actual task in our tasks list to get its calculated progress
                        if let Some(task) = tasks.iter().find(|t| t.name == *running_task_name && t.status == "STATE_RUNNING") {
                            // Use the task's progress percentage (0-100)
                            let task_progress_ratio = task.progress as f64 / 100.0;

                            // Weight of this task in the overall time
                            let task_weight = *expected_duration as f64 / total_seconds as f64;

                            // Add weighted progress from running task
                            time_based_progress += task_weight * task_progress_ratio * 100.0;
                        } else {
                            // Fallback if we can't find the task - calculate progress directly
                            let now = chrono::Utc::now();
                            let elapsed = now.signed_duration_since(*started_at).num_seconds() as f64;

                            // Ratio of elapsed time to expected duration, capped at 100%
                            let task_progress_ratio = if *expected_duration > 0 {
                                (elapsed / *expected_duration as f64).min(1.0)
                            } else {
                                0.0
                            };

                            // Weight of this task in the overall time
                            let task_weight = *expected_duration as f64 / total_seconds as f64;

                            // Add partial progress from running task
                            time_based_progress += task_weight * task_progress_ratio * 100.0;
                        }
                    }

                    // Ratchet mechanism - ensure progress doesn't go backwards
                    // Get the previous progress for this workflow from the database
                    let previous_progress = match crate::db::get_completed_workflow(&machine.id).await {
                        Ok(Some((existing_wf, _))) => {
                            // Only use previous progress if we're in the same workflow state
                            if existing_wf.state == state {
                                existing_wf.progress as f64
                            } else {
                                0.0 // Different state, reset progress
                            }
                        },
                        _ => 0.0, // No previous workflow info
                    };

                    // Take the maximum of current progress and previous progress
                    let final_progress = time_based_progress.max(previous_progress);

                    // Cap at 100%
                    final_progress.min(100.0) as u8
                } else {
                    0
                };

                // Calculate estimated completion time using template-specific timing data
                let estimated_completion = if state != "STATE_SUCCESS" && state != "STATE_FAILED" && !tasks.is_empty() {
                    if let (Some((_task_name, expected_duration)), Some(started_at)) = (&running_task_info, &running_task_started_at) {
                        // Calculate elapsed time since the task started
                        let now = chrono::Utc::now();
                        let elapsed = now.signed_duration_since(*started_at).num_seconds() as i64;

                        // Calculate remaining time for current task
                        let remaining_seconds = *expected_duration as i64 - elapsed;
                        let remaining_seconds = remaining_seconds.max(0); // Ensure non-negative

                        // If we're near completion of this task, look ahead to how much time is left overall
                        if remaining_seconds < 10 {
                            // Sum the durations of all remaining tasks
                            let mut remaining_total = remaining_seconds;
                            let mut found_current = false;

                            for task in &tasks {
                                if found_current {
                                    // This is a future task
                                    remaining_total += task.duration as i64;
                                } else if task.name == *_task_name && task.status == "STATE_RUNNING" {
                                    // This is the current task, we've found it
                                    found_current = true;
                                }
                            }

                            format_remaining_time(remaining_total)
                        } else {
                            // Just focus on current task
                            format_remaining_time(remaining_seconds)
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // If the workflow completed successfully, store the timing information with template reference
                if state == "STATE_SUCCESS" && tasks.iter().all(|t| t.status == "STATE_SUCCESS") {
                    store_timing_info(template_ref, &tasks);

                    // Send a machine_updated event
                    if let Some(event_manager) = get_event_manager() {
                        info!("Sending machine_updated event for completed workflow: {}", machine.id);
                        // TODO: Handle error
                        event_manager.send(format!("machine_updated:{}", machine.id));
                    }
                }

                // If the workflow failed, update the machine status to Error
                if state == "STATE_FAILED" {
                    if let Err(e) = update_machine_status_on_failure(machine).await {
                        warn!("Failed to update machine status after workflow failure: {}", e);
                    }

                    // Send a machine_updated event
                    if let Some(event_manager) = get_event_manager() {
                        info!("Sending machine_updated event for failed workflow: {}", machine.id);
                        // TODO: Handle error
                        event_manager.send(format!("machine_updated:{}", machine.id));
                    }
                }

                // Only mark as Ready if ALL tasks are complete successfully
                if state == "STATE_SUCCESS" && tasks.iter().all(|t| t.status == "STATE_SUCCESS") {
                    if let Err(e) = update_machine_status_on_success(machine).await {
                        warn!("Failed to update machine status after workflow success: {}", e);
                    }
                }

                // Also send an update event for normal workflow progress
                if state == "STATE_RUNNING" {
                    // Send a machine_updated event for real-time progress updates
                    if let Some(event_manager) = get_event_manager() {
                        info!("Sending machine_updated event for workflow progress: {}", machine.id);
                        // TODO: Handle error
                        event_manager.send(format!("machine_updated:{}", machine.id));
                    }
                }

                let workflow_info = WorkflowInfo {
                    state: state.to_string(),
                    current_action,
                    progress,
                    tasks,
                    estimated_completion,
                    template_name: template_ref.to_string(),
                };

                Ok(Some(workflow_info))
            } else {
                info!("No status information found for workflow {}", workflow_name);
                Ok(None)
            }
        },
        Err(KubeError::Api(ae)) if ae.code == 404 => {
            info!("No workflow found with name: {}", workflow_name);
            Ok(None)
        },
        Err(e) => {
            error!("Error fetching workflow {}: {}", workflow_name, e);
            Err(anyhow!("Error fetching workflow: {}", e))
        }
    }
}

// Helper function to get the event manager
fn get_event_manager() -> Option<&'static crate::event_manager::EventManager> {
    // Get the event manager from the AppState
    // This is a simplified approach - in a real implementation you would
    // pass the event manager as a parameter to avoid static references

    // Access the global event manager reference
    if let Ok(event_manager_ref) = crate::EVENT_MANAGER_REF.read() {
        if let Some(event_manager) = event_manager_ref.as_ref() {
            // Safety: we know the EventManager will live for the duration of the program
            // since it's stored in a static Arc
            let static_ref = unsafe {
                std::mem::transmute::<&crate::event_manager::EventManager, &'static crate::event_manager::EventManager>(
                    event_manager.as_ref()
                )
            };
            return Some(static_ref);
        }
    }

    None // For now, we'll rely on callers to send events properly
}

// Update machine status when workflow fails
async fn update_machine_status_on_failure(machine: &Machine) -> Result<()> {
    use dragonfly_common::models::MachineStatus;

    info!("Workflow failed for machine {}, updating status to Error", machine.id);

    let mut updated_machine = machine.clone();
    updated_machine.status = MachineStatus::Error("OS installation failed".to_string());

    crate::db::update_machine(&updated_machine).await?;
    Ok(())
}

// Update machine status when workflow succeeds
async fn update_machine_status_on_success(machine: &Machine) -> Result<()> {
    use dragonfly_common::models::MachineStatus;
    use dragonfly_common::models::Machine;
    use anyhow::anyhow;

    info!("Workflow completed successfully for machine {}, updating status to Ready", machine.id);

    // First update just the status for reliability
    match crate::db::update_status(&machine.id, MachineStatus::Ready).await {
        Ok(true) => {
            info!("Successfully updated status to Ready for machine {}", machine.id);

            // Calculate deployment duration
            if machine.status == MachineStatus::InstallingOS {
                let now = chrono::Utc::now();
                let duration = now.signed_duration_since(machine.updated_at).num_seconds();

                // Try to update the duration separately
                if let Err(e) = crate::db::update_machine(&Machine {
                    last_deployment_duration: Some(duration),
                    ..machine.clone()
                }).await {
                    warn!("Failed to update deployment duration: {}", e);
                }
            }

            Ok(())
        },
        Ok(false) => {
            error!("Failed to update machine status - machine not found: {}", machine.id);
            Err(anyhow!("Machine not found"))
        },
        Err(e) => {
            error!("Failed to update machine status: {}", e);
            Err(e)
        }
    }
}

// Helper function to format remaining time in a human-readable way
fn format_remaining_time(seconds: i64) -> Option<String> {
    if seconds <= 0 {
        return Some("Completing soon".to_string());
    }

    if seconds < 60 {
        return Some(format!("Less than a minute remaining"));
    }

    let minutes = seconds / 60;
    if minutes < 60 {
        return Some(format!("Approximately {} minute{} remaining",
            minutes, if minutes == 1 { "" } else { "s" }));
    }

    let hours = minutes / 60;
    let remaining_minutes = minutes % 60;

    if remaining_minutes == 0 {
        Some(format!("Approximately {} hour{} remaining",
            hours, if hours == 1 { "" } else { "s" }))
    } else {
        Some(format!("Approximately {} hour{} and {} minute{} remaining",
            hours, if hours == 1 { "" } else { "s" },
            remaining_minutes, if remaining_minutes == 1 { "" } else { "s" }))
    }
}

// Helper function to check if a workflow has timed out
fn is_workflow_timed_out(status: &serde_json::Value, current_action: Option<&str>) -> bool {
    // First, check the state - we only consider timing out workflows that are in STATE_RUNNING
    let state = status.get("state").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
    if state != "STATE_RUNNING" {
        return false;
    }

    // Check if the current action is kexec to boot OS
    if current_action != Some("kexec to boot OS") {
        return false;
    }

    // Try to get the time for the last action
    if let Some(tasks) = status.get("tasks") {
        if let Some(tasks_array) = tasks.as_array() {
            for task_obj in tasks_array {
                if let Some(actions) = task_obj.get("actions") {
                    if let Some(actions_array) = actions.as_array() {
                        if let Some(last_action) = actions_array.last() {
                            if last_action.get("name").and_then(|n| n.as_str()) == Some("kexec to boot OS") {
                                if let Some(started_at_str) = last_action.get("startedAt").and_then(|s| s.as_str()) {
                                    // Try to parse the started_at time
                                    if let Ok(started_at) = chrono::DateTime::parse_from_rfc3339(started_at_str) {
                                        let now = chrono::Utc::now();
                                        let elapsed = now.signed_duration_since(started_at);

                                        // If it's been more than 30 minutes, consider it timed out
                                        if elapsed.num_minutes() > 30 {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

// Clean up historical timing data to maintain only MAX_TIMING_HISTORY entries per template/action
pub async fn cleanup_historical_timings() -> anyhow::Result<()> {
    // Get write lock on timings and collect data to save
    let to_save = {
        let mut timings = HISTORICAL_TIMINGS.write().map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let mut data = Vec::new();

        // Clone the data we need
        for (template_name, actions) in timings.iter() {
            for (action_name, durations) in actions.iter() {
                data.push((
                    template_name.clone(),
                    action_name.clone(),
                    durations.clone()
                ));
            }
        }

        // Clear the in-memory timings
        timings.clear();
        data
    }; // Lock is dropped here

    // Save each timing to the database
    for (template_name, action_name, durations) in to_save {
        if let Err(e) = crate::db::save_template_timing(&template_name, &action_name, &durations).await {
            error!("Failed to save timing data: {}", e);
        }
    }

    Ok(())
}

// Periodically clean up historical timing data
pub async fn start_timing_cleanup_task(mut shutdown_rx: tokio::sync::watch::Receiver<()>) {
    tokio::spawn(async move {
        // Run the cleanup task every 24 hours
        let cleanup_interval = std::time::Duration::from_secs(24 * 60 * 60);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(cleanup_interval) => {
                    info!("Running timing cleanup task");
                    if let Err(e) = cleanup_historical_timings().await {
                        error!("Error during timing cleanup: {}", e);
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping timing cleanup task.");
                    break; // Exit the loop
                }
            }
        }
    });
}

// Calculate progress based on completed tasks
fn calculate_progress(tasks: &[TaskInfo]) -> u8 {
    if tasks.is_empty() {
        return 0;
    }

    // Calculate percentage based on completed tasks (this is now just a fallback)
    let total_tasks = tasks.len();
    let completed_tasks = tasks.iter().filter(|t| t.status == "STATE_SUCCESS").count();

    ((completed_tasks as f64 / total_tasks as f64) * 100.0).min(99.0) as u8
}

// Estimate completion time based on historical timing data
#[allow(dead_code)]
async fn estimate_completion_time(template_name: &str, current_action: &str, tasks: &[TaskInfo], state: &str) -> (Option<std::time::Duration>, u8) {
    // Load all template timing data
    let timings = match crate::db::load_template_timings().await {
        Ok(t) => t,
        Err(_) => return (None, calculate_progress(tasks)),
    };

    // Calculate time remaining
    let mut total_estimated_time = 0u64;
    let mut time_elapsed = 0u64;
    let mut current_action_found = false;

    // First pass: collect all task names to build a complete sequence
    let mut all_task_names = Vec::new();
    for task in tasks {
        all_task_names.push(task.name.clone());
    }

    // Second pass: calculate estimates
    for task_name in &all_task_names {
        // Find historical timing data for this action
        let timing_data = timings.iter().find(|t|
            t.template_name == template_name &&
            t.action_name == *task_name
        );

        // Get average duration for this action
        let avg_duration = match timing_data {
            Some(data) if !data.durations.is_empty() => {
                let sum: u64 = data.durations.iter().sum();
                sum / data.durations.len() as u64
            },
            _ => {
                // If no timing data found, we can't estimate
                // Return the fallback progress calculation
                return (None, calculate_progress(tasks));
            }
        };

        total_estimated_time += avg_duration;

        // If we haven't reached the current action yet, add to elapsed time
        if task_name != current_action {
            if !current_action_found {
                time_elapsed += avg_duration;
            }
        } else {
            current_action_found = true;

            // For the current action, add partial time based on task state
            if state == "STATE_RUNNING" {
                // Assume we're halfway through the current action
                time_elapsed += avg_duration / 2;
            }
        }
    }

    // Calculate time remaining and progress percentage
    let time_remaining = if time_elapsed < total_estimated_time {
        Some(std::time::Duration::from_millis(total_estimated_time - time_elapsed))
    } else {
        None
    };

    let progress = if total_estimated_time > 0 {
        ((time_elapsed as f64 / total_estimated_time as f64) * 100.0).min(99.0) as u8
    } else {
        calculate_progress(tasks)
    };

    (time_remaining, progress)
}

// Start a background task to poll for workflow updates
pub async fn start_workflow_polling_task(
    event_manager: std::sync::Arc<crate::event_manager::EventManager>,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>
) {
    use dragonfly_common::models::MachineStatus;
    use std::collections::HashMap;
    use std::time::Duration;

    // Clone the event manager for the task
    let event_manager_clone = event_manager.clone();

    tokio::spawn(async move {
        let poll_interval = Duration::from_secs(1);
        info!("Starting workflow polling task with interval of {:?}", poll_interval);

        // Track the last seen workflow state by machine ID
        let mut last_seen_states: HashMap<uuid::Uuid, (String, Option<String>)> = HashMap::new();

        loop {
            // Wait for the poll interval or shutdown signal
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {
                    // Get all machines with InstallingOS status
                    let machines = match crate::db::get_machines_by_status(MachineStatus::InstallingOS).await {
                        Ok(machines) => machines,
                        Err(e) => {
                            error!("Failed to get machines for workflow polling: {}", e);
                            continue;
                        }
                    };

                    if machines.is_empty() {
                        // No machines are currently installing OS
                        continue;
                    }

                    // Check each machine's workflow
                    for machine in machines.iter() {
                        match get_workflow_info(machine).await {
                            Ok(Some(info)) => {
                                let current_state = (info.state.clone(), info.current_action.clone());

                                if let Some(last_state) = last_seen_states.get(&machine.id) {
                                    if *last_state != current_state {
                                        info!("Workflow update: machine={} old_state={} -> new_state={} action={:?}",
                                            machine.id,
                                            last_state.0,
                                            current_state.0,
                                            current_state.1
                                        );
                                        // Send machine updated event on state change
                                        // TODO: Handle error
                                        event_manager_clone.send(format!("machine_updated:{}", machine.id));
                                        last_seen_states.insert(machine.id, current_state);
                                    }
                                } else {
                                    // First time seeing this machine - log it once
                                    info!("New workflow: machine={} state={} action={:?}",
                                        machine.id,
                                        current_state.0,
                                        current_state.1
                                    );

                                    // Send initial machine updated event
                                    // TODO: Handle error
                                    event_manager_clone.send(format!("machine_updated:{}", machine.id));

                                    // Add to last seen states
                                    last_seen_states.insert(machine.id, current_state);
                                }
                            },
                            Ok(None) => {
                                // If we previously had a workflow but now it's gone, send an event
                                if last_seen_states.remove(&machine.id).is_some() {
                                    info!("Workflow completed for machine {}", machine.id);
                                    // TODO: Handle error
                                    event_manager_clone.send(format!("machine_updated:{}", machine.id));
                                }
                            },
                            Err(e) => {
                                error!("Error fetching workflow for machine {}: {}", machine.id, e);
                            }
                        }
                    }

                    // Clean up stale entries without logging - just remove machines no longer installing OS
                    let active_machine_ids: std::collections::HashSet<uuid::Uuid> =
                        machines.iter().map(|m| m.id).collect();

                    last_seen_states.retain(|machine_id, _| active_machine_ids.contains(machine_id));
                }
                _ = shutdown_rx.changed() => {
                    info!("Shutdown signal received, stopping workflow polling task.");
                    break; // Exit the loop
                }
            }
        }
    });
}

// Get workflow information from Kubernetes for a specific machine ID
pub async fn get_workflow_info_by_id(id: &uuid::Uuid) -> Result<Option<WorkflowInfo>> {
    // First, find the machine by ID
    match crate::db::get_machine_by_id(id).await {
        Ok(Some(machine)) => {
            // Use the existing get_workflow_info function once we have the machine
            get_workflow_info(&machine).await
        },
        Ok(None) => {
            warn!("Cannot get workflow info: Machine with ID {} not found", id);
            Ok(None)
        },
        Err(e) => {
            error!("Error fetching machine with ID {}: {}", id, e);
            Err(anyhow!("Error fetching machine: {}", e))
        }
    }
}
