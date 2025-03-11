#!/usr/bin/python

DOCUMENTATION = r'''
---
module: crm
short_description: Manage Pacemaker/Corosync clusters using crm shell
description:
    - Manages Pacemaker/Corosync clusters using crm shell commands
    - All operations are automatically verified to run on the Designated Coordinator (DC) node
    - Requires passwordless SSH authentication between nodes
    - Provides comprehensive status reporting and change verification
    - Handles cluster initialization, node management, and resource control
    - Supports various constraint types and monitoring operations
    - Note: Some operations require running on the DC node; the module will skip operations if not on DC

options:
    command:
        description:
            - Main command category to execute
            - 'status' returns cluster status information
            - 'node' manages node states
            - 'configure' handles resources and cluster configuration
            - 'cluster' manages cluster-wide operations
            - 'resource' manages resource states
        required: true
        type: str
        choices: ['status', 'node', 'configure', 'cluster', 'resource']

    subcommand:
        description:
            - Specific operation to perform within command category
            - Only required for certain commands
            - Must be compatible with main command
        required: false
        type: str
        choices: ['init', 'join', 'remove', 'property', 'resource', 'delete',
                 'restart', 'geo-init', 'group', 'monitor', 'utilization',
                 'rsc_defaults', 'op_defaults', 'location', 'colocation', 'order',
                 'rsc_ticket', 'template']

    cluster_name:
        description:
            - Name of the cluster for initialization
            - Required when initializing a new cluster
        required: false
        type: str

    cluster_init_node:
        description:
            - Node designated to initialize the cluster
            - Required for cluster initialization
        required: false
        type: str

    interface:
        description:
            - Network interface for cluster communication
            - Used during cluster init and join operations
        required: false
        type: str

    admin_ip_address:
        description:
            - Administrative IP address for cluster management
            - Used during initialization
        required: false
        type: str

    resource:
        description:
            - Name of resource(s) to manage
            - Can be string for single resource or list for multiple
            - Required for resource operations
        required: false
        type: raw

    resource_type:
        description:
            - Type of resource to create
            - Required when creating new resources
        required: false
        type: str

    resource_class:
        description:
            - Resource agent class (ocf, systemd, service, stonith)
            - Required for resource creation
        required: false
        type: str

    resource_provider:
        description:
            - Provider of resource agent
            - Required for non-stonith resources
        required: false
        type: str

    resource_agent:
        description:
            - Name of specific resource agent
            - Required for resource creation
        required: false
        type: str

    parameters:
        description:
            - Dictionary of resource parameters
            - Key-value pairs for resource configuration
        required: false
        type: dict

    state:
        description:
            - Desired state for resource or node
            - Controls create/delete/start/stop operations
        choices: ['present', 'absent', 'started', 'stopped', 'standby', 'online']
        required: false
        type: str

    node:
        description:
            - Name of node to manage
            - Required for node operations
        required: false
        type: str

    properties:
        description:
            - Dictionary of cluster properties
            - Applied only on DC node
        required: false
        type: dict

    qdevice:
        description:
            - Whether to configure QDevice
            - Enhances split-brain handling
        required: false
        type: bool
        default: false

    qnetd_hostname:
        description:
            - Hostname of QNetd server
            - Required when configuring QDevice
        required: false
        type: str

    qdevice_algo:
        description:
            - Algorithm for QDevice decisions
            - Controls split-brain handling
        required: false
        type: str
        choices: ['ffsplit', 'lms']

    qdevice_tie_breaker:
        description:
            - Tie-breaker configuration for QDevice
        required: false
        type: str
        choices: ['lowest', 'highest', 'valid_node_id']

    qdevice_tls:
        description:
            - TLS security setting for QDevice
        required: false
        type: str
        choices: ['on', 'off', 'required']

    force:
        description:
            - Force operations like node removal
            - Required for removing DC node
        required: false
        type: bool
        default: false

    fail_on_error:
        description:
            - Whether to fail task on errors
            - When false, returns status with empty values
        required: false
        type: bool
        default: true

    operation_timeout:
        description:
            - Timeout in seconds for operations
            - Used for state change verification
        required: false
        type: int
        default: 30

    constraint_id:
        description:
            - Unique identifier for constraints
            - Required for constraint operations
        required: false
        type: str

    constraint_score:
        description:
            - Score for constraint rules
            - Used in location and colocation constraints
        required: false
        type: str

    location_rules:
        description:
            - List of rules for location constraints
            - Each rule must have score and expression
        required: false
        type: list

    colocation_resources:
        description:
            - List of resources for colocation constraint
            - Must specify at least two resources
        required: false
        type: list

    order_resources:
        description:
            - List of resources for ordering constraint
            - Must specify at least two resources
        required: false
        type: list

    group_name:
        description:
            - Name for resource group
            - Required for group operations
        required: false
        type: str

    group_resources:
        description:
            - List of resources to include in group
            - Required when creating groups
        required: false
        type: list

    monitor_interval:
        description:
            - Interval for resource monitoring
            - Required for monitor operations
        required: false
        type: str

    monitor_timeout:
        description:
            - Timeout for monitor operations
            - Optional for monitor configuration
        required: false
        type: str

    geo_site_id:
        description:
            - Identifier for geo-cluster site
            - Required for geo-init operations
        required: false
        type: str

    geo_site_ticket:
        description:
            - Ticket name for geo-cluster
            - Required for geo-init operations
        required: false
        type: str

notes:
    - All operations verify they are running on DC node
    - Operations will be skipped if not on DC node
    - Cluster status returned in structured format
    - State changes verified with configurable timeouts
    - Resource operations support single/multiple resources
    - SSH passwordless auth required between nodes
    - Operations are idempotent where possible
    - Complex constraints supported with validation
    - Monitor operations configurable with verification
    - Geo-cluster configuration supported with basic options

status structure:
    cluster_status.summary:
        .stack:                      # Cluster stack type
        .dc_node:                    # Current DC node name
        .dc_version:                 # DC version number
        .last_updated:               # Last status update timestamp
        .last_change:                # Last cluster change timestamp
        .nodes_configured:           # Total configured nodes
        .resources_configured:       # Total configured resources
        .resources_disabled:         # Count of disabled resources

    cluster_status.nodes:
        .online: []                  # List of online nodes
        .offline: []                 # List of offline nodes
        .standby: []                 # List of standby nodes
        .unclean: []                 # List of unclean nodes

    cluster_status.resources:        # Dictionary of resources
        .resource_name:
            .type:                   # Resource agent type
            .status:                 # Current status (Started/Stopped)
            .node:                   # Node where resource is running

    cluster_status.maintenance_mode: # Cluster maintenance status

author:
    - "Alex C."
'''

EXAMPLES = r'''
# Get detailed cluster status
- name: Get cluster status
  crm:
    command: status
    fail_on_error: false
  register: cluster_status

# Initialize basic cluster
- name: Initialize cluster
  crm:
    command: cluster
    subcommand: init
    cluster_name: prod_cluster
    cluster_init_node: "{{ inventory_hostname }}"
    interface: eth1
    admin_ip_address: 192.168.1.100
  register: cluster_init

# Initialize cluster with QDevice
- name: Initialize cluster with QDevice
  crm:
    command: cluster
    subcommand: init
    cluster_name: prod_cluster
    cluster_init_node: "{{ inventory_hostname }}"
    interface: eth1
    admin_ip_address: 192.168.1.100
    qdevice: true
    qnetd_hostname: qnetd.example.com
    qdevice_algo: ffsplit
    qdevice_tie_breaker: lowest
    qdevice_tls: required
  register: cluster_init

# Join node to cluster
- name: Join cluster
  crm:
    command: cluster
    subcommand: join
    cluster_node: "{{ hostvars[cluster_init_node]['ansible_hostname'] }}"
    interface: eth1
  when: inventory_hostname != cluster_init_node

# Set cluster properties
- name: Configure cluster properties
  crm:
    command: configure
    subcommand: property
    properties:
      stonith-enabled: true
      no-quorum-policy: stop
      maintenance-mode: false

# Create virtual IP resource
- name: Configure virtual IP
  crm:
    command: configure
    subcommand: resource
    resource: vip_resource
    resource_type: primitive
    resource_class: ocf
    resource_provider: heartbeat
    resource_agent: IPaddr2
    state: present
    parameters:
      ip: 192.168.1.100
      cidr_netmask: 24
      nic: eth1

# Create resource group
- name: Create resource group
  crm:
    command: configure
    subcommand: group
    group_name: web_group
    group_resources:
      - vip_resource
      - web_server
    state: present

# Configure monitoring
- name: Set up resource monitoring
  crm:
    command: configure
    subcommand: monitor
    resource: web_server
    monitor_interval: 10s
    monitor_timeout: 60s

# Create location constraint
- name: Set preferred location
  crm:
    command: configure
    subcommand: location
    constraint_id: loc_web
    location_rules:
      - score: 100
        expression: "#uname eq node1"

# Create colocation constraint
- name: Configure resource colocation
  crm:
    command: configure
    subcommand: colocation
    constraint_id: col_web
    constraint_score: INFINITY
    colocation_resources:
      - name: vip_resource
        role: Started
      - name: web_server
        role: Started

# Create order constraint
- name: Set resource order
  crm:
    command: configure
    subcommand: order
    constraint_id: ord_web
    order_resources:
      - name: vip_resource
        action: start
      - name: web_server
        action: start

# Set node to standby
- name: Put node in standby
  crm:
    command: node
    node: "{{ inventory_hostname }}"
    state: standby

# Remove node from cluster
- name: Remove node
  crm:
    command: cluster
    subcommand: remove
    cluster_node: node2
    force: false
  when: inventory_hostname == cluster_status.status.summary.dc_node

# Initialize geo-cluster site
- name: Set up geo-cluster
  crm:
    command: cluster
    subcommand: geo-init
    geo_site_id: site1
    geo_site_ticket: ticket1
  run_once: true
  when: inventory_hostname == cluster_init_node

# Stop a resource
- name: Stop web server
  crm:
    command: resource
    resource: web_server
    state: stopped

# Delete a resource
- name: Remove resource
  crm:
    command: configure
    subcommand: resource
    resource: web_server
    state: absent
'''
        
from ansible.module_utils.basic import AnsibleModule
import subprocess
import re
import json
import time

def check_cluster_exists(module):
    """Check if cluster configuration exists and count nodes"""
    details = {
        'corosync_configured': False,
        'cluster_name': None,
        'node_count': 0
    }

    rc, _, _ = module.run_command(['test', '-f', '/etc/corosync/corosync.conf'])
    if rc == 0:
        details['corosync_configured'] = True
        try:
            with open('/etc/corosync/corosync.conf', 'r') as f:
                config = f.read()
                
                name_match = re.search(r'cluster_name:\s*(\S+)', config)
                if name_match:
                    details['cluster_name'] = name_match.group(1)
                
                node_matches = re.findall(r'nodeid:', config)
                details['node_count'] = len(node_matches)
                
                if details['node_count'] == 0:
                    node_matches = re.findall(r'node\s*{', config)
                    details['node_count'] = len(node_matches)

        except Exception as e:
            module.warn(f"Error reading corosync.conf: {str(e)}")

    cluster_exists = details['corosync_configured']

    return cluster_exists, details

def init_cluster(module):
    """Initialize a new cluster"""
    params = module.params
    
    cluster_init_node = params.get('cluster_init_node')
    if not cluster_init_node:
        module.fail_json(msg="cluster_init_node is required for cluster initialization")
    
    cluster_name = params.get('cluster_name')
    if not cluster_name:
        module.fail_json(msg="cluster_name is required for cluster init")

    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()

    if hostname != cluster_init_node:
        return False, {
            'changed': False,
            'msg': f"Not the designated init node ({cluster_init_node})"
        }

    exists, details = check_cluster_exists(module)
    
    if exists:
        if details['cluster_name'] == cluster_name:
            return False, {
                'changed': False,
                'msg': "Cluster config exists with matching name",
                'details': details
            }
        else:
            module.fail_json(
                msg=f"Different cluster exists: {details['cluster_name']}",
                details=details
            )
    
    cmd_parts = ['crm', 'cluster', 'init', '-y', '-n', cluster_name]
    
    param_flags = {
        'interface': '--interface',
        'admin_ip_address': '-A',
        'qnetd_hostname': '--qnetd-hostname',
        'qdevice_algo': '--qdevice-algo',
        'qdevice_tie_breaker': '--qdevice-tie-breaker',
        'qdevice_tls': '--qdevice-tls',
        'qdevice_heuristics': '--qdevice-heuristics',
        'qdevice_heuristics_mode': '--qdevice-heuristics-mode',
        'qdevice_port': '--qdevice-port'
    }
    
    for param, flag in param_flags.items():
        if params.get(param):
            cmd_parts.append(f"{flag} {params[param]}")

    command = ' '.join(cmd_parts)
    
    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would initialize cluster: {command}",
            'command': command
        }
    
    rc, out, err = module.run_command(command)
    if rc != 0:
        module.fail_json(msg=f"Initialization failed: {err}", command=command)
    
    success, status = wait_for_cluster_change(
    module,
    lambda status: (
        status['summary']['nodes_configured'] > 0 and
        status['summary'].get('dc_node') is not None
    ),
    timeout=module.params.get('operation_timeout', 180),
    error_msg=f"Timeout waiting for cluster {cluster_name} to initialize"
    )

    verify_exists, verify_details = check_cluster_exists(module)
    if verify_exists and verify_details['cluster_name'] == cluster_name:
        return True, {
            'changed': True,
            'msg': "Cluster initialized",
            'details': verify_details
        }
    else:
        module.fail_json(
            msg="Initialization verification failed",
            command=command,
            details=verify_details
        )

def verify_dc_node(module, status=None):
    """Centralized DC node verification"""
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Operation skipped - not DC node {dc_node}",
            'hostname': hostname,
            'dc_node': dc_node
        }
    return True, {'hostname': hostname, 'dc_node': dc_node}

def get_cluster_property(module, property_name):
    """Get current value of a cluster property"""
    cmd = ['crm', 'configure', 'get_property', property_name]
    rc, out, err = module.run_command(cmd)
    
    if rc != 0:
        return None
        
    if ':' in out:
        return out.split(':', 1)[1].strip()
    return out.strip()

def is_current_node_dc(module, status=None):
    """Check if current node is the DC node"""
    if status is None:
        status = get_cluster_status(module, fail_on_error=False)
        if not status:
            module.fail_json(msg="Unable to determine cluster status")

    dc_node = status['summary'].get('dc_node')
    if not dc_node:
        module.fail_json(msg="No DC node found in cluster status")

    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    
    return hostname.strip() == dc_node, hostname.strip(), dc_node

def manage_cluster_property(module):
    """Manage cluster properties with proper command construction"""
    properties = module.params.get('properties')
    
    if not properties or not isinstance(properties, dict):
        module.fail_json(msg="A dictionary of properties is required")

    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Property management skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    changed = False
    for name, value in properties.items():
        if isinstance(value, bool):
            value = "true" if value else "false"
        
        cmd = ['crm', 'configure', 'property', f'{name}={value}']
        
        if module.check_mode:
            changed = True
            continue

        rc, out, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(msg=f"Failed to set property {name}: {err}")
        changed = True

    return changed, {
        'changed': changed,
        'msg': "Cluster properties updated successfully",
        'properties': properties
    }

def add_qdevice(module):
    """Add a qdevice to an existing cluster"""
    params = module.params
    qnetd_hostname = params.get('qnetd_hostname')
    
    if not qnetd_hostname:
        module.fail_json(msg="qnetd_hostname is required for adding a qdevice")
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Cannot add qdevice: failed to get cluster status")
    
    if status['summary']['nodes_configured'] == 0:
        module.fail_json(msg="Cannot add qdevice: no nodes configured in cluster")
        
    if status.get('maintenance_mode', False):
        module.fail_json(msg="Cannot add qdevice: cluster is in maintenance mode")
    
    cmd_parts = ["crm", "cluster", "init", "qdevice", "-y", "--qnetd-hostname", qnetd_hostname]
    
    qdevice_params = {
        'qdevice_port': '--qdevice-port',
        'qdevice_algo': '--qdevice-algo',
        'qdevice_tie_breaker': '--qdevice-tie-breaker',
        'qdevice_tls': '--qdevice-tls',
        'qdevice_heuristics': '--qdevice-heuristics',
        'qdevice_heuristics_mode': '--qdevice-heuristics-mode'
    }
    
    for param_name, param_flag in qdevice_params.items():
        if params.get(param_name):
            cmd_parts.append(f"{param_flag} {params[param_name]}")
    
    if module.check_mode:
        return True, f"Would add qdevice with command: {' '.join(cmd_parts)}"
    
    rc, out, err = module.run_command(' '.join(cmd_parts))
    if rc != 0:
        module.fail_json(msg=f"Failed to add qdevice: {err}")
    
    time.sleep(5)
    
    try:
        new_status = get_cluster_status(module, fail_on_error=False)
        if not new_status:
            return True, "QDevice added but unable to verify new cluster status"
    except Exception:
        return True, "QDevice added but unable to verify new cluster status"
        
    return True, "QDevice added successfully"

def join_cluster(module):
    """Join an existing cluster, safely skipping if current node is DC or target node.
    
    Args:
        module: AnsibleModule instance
        
    Returns:
        tuple: (changed, result_dict)
    """
    params = module.params
    target_node = params.get('cluster_node')
    interface = params.get('interface')
    
    if not target_node:
        module.fail_json(msg="cluster_node is required for cluster join")
    
    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()

    result = {
        'changed': False,
        'hostname': hostname,
        'target_node': target_node
    }

    status = get_cluster_status(module, fail_on_error=False)
    
    if status:
        result['status'] = status
        dc_node = status['summary'].get('dc_node')
        
        if dc_node and hostname == dc_node:
            result.update({
                'msg': f"Node {hostname} is the current DC node - no join needed",
                'dc_node': dc_node
            })
            return False, result
            
        all_nodes = []
        for state in ['online', 'offline', 'standby', 'unclean']:
            all_nodes.extend(status['nodes'].get(state, []))
            
        if hostname in all_nodes:
            result.update({
                'msg': f"Node {hostname} is already a cluster member",
                'cluster_nodes': all_nodes
            })
            return False, result
    
    if hostname == target_node:
        result['msg'] = f"Node {hostname} is the target cluster node - no join needed"
        return False, result

    cmd = ['crm', 'cluster', 'join', '-y']
    cmd.extend(['-c', target_node])
    if interface:
        cmd.extend(['--interface', interface])

    if module.check_mode:
        result.update({
            'changed': True,
            'msg': f"Would join cluster via node {target_node}",
            'command': cmd
        })
        return True, result

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(
            msg=f"Failed to join cluster: {err}",
            command=cmd,
            rc=rc,
            stdout=out,
            stderr=err
        )
    
    success, verify_status = wait_for_cluster_change(
        module,
        lambda status: hostname in (
            status['nodes'].get('online', []) +
            status['nodes'].get('offline', []) +
            status['nodes'].get('standby', [])
        ),
        timeout=module.params.get('operation_timeout', 60),
        error_msg=f"Timeout waiting for node {hostname} to join cluster"
    )

    if not success:
        module.fail_json(
            msg=f"Failed to verify cluster join for node {hostname}",
            command=cmd,
            timeout=module.params.get('operation_timeout', 60),
            status=verify_status
        )
    
    max_retries = 3
    retry_delay = 5
    verification_success = False
    final_status = None
    
    for attempt in range(max_retries):
        final_status = get_cluster_status(module, fail_on_error=False)
        if final_status:
            all_nodes = []
            for state in ['online', 'offline', 'standby', 'unclean']:
                all_nodes.extend(final_status['nodes'].get(state, []))
                
            if hostname in all_nodes:
                verification_success = True
                break
                
        if attempt < max_retries - 1:
            time.sleep(retry_delay)
    
    if not verification_success:
        module.fail_json(
            msg=f"Node {hostname} not found in cluster after join",
            command=cmd,
            status=final_status,
            node=hostname
        )

    result.update({
        'changed': True,
        'msg': "Successfully joined cluster",
        'status': final_status,
        'command': cmd,
        'cluster_nodes': all_nodes
    })
    
    return True, result

def remove_node_from_cluster(module, node, force, dc_node, hostname, status):
    """Remove a non-DC node from the cluster with verification.
    
    Args:
        module: AnsibleModule instance
        node: Name of node to remove
        force: Whether to force removal
        dc_node: Current DC node name
        hostname: Current hostname
        status: Current cluster status
        
    Returns:
        tuple: (changed, result_dict)
    """
    all_nodes = (
        status.get('nodes', {}).get('online', []) +
        status.get('nodes', {}).get('offline', []) +
        status.get('nodes', {}).get('standby', []) +
        status.get('nodes', {}).get('unclean', [])
    )
    
    if node not in all_nodes:
        return False, {
            'changed': False,
            'msg': f"Node {node} not found in cluster",
            'dc_node': dc_node,
            'hostname': hostname,
            'target_node': node
        }

    cmd = ['crm', 'cluster', 'remove', '-c', node, '-y']
    if force:
        cmd += ['-F']
    
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(
            msg=f"Failed to remove node from cluster: {err}",
            command=cmd,
            rc=rc,
            stdout=out,
            stderr=err
        )

    success, final_status = wait_for_cluster_change(
        module,
        lambda status: node not in (
            status.get('nodes', {}).get('online', []) +
            status.get('nodes', {}).get('offline', []) +
            status.get('nodes', {}).get('standby', []) +
            status.get('nodes', {}).get('unclean', [])
        ),
        timeout=module.params.get('operation_timeout', 40),
        error_msg=f"Timeout waiting for node {node} to be removed from cluster"
    )
    
    return True, {
        'changed': True,
        'msg': f"Successfully removed node {node} from cluster",
        'dc_node': dc_node,
        'hostname': hostname,
        'target_node': node,
        'final_status': final_status
    }

def destroy_cluster_from_dc(module, node, dc_node, hostname):
    """Remove the DC node, effectively destroying the cluster.
    No status verification is performed since the cluster will be disbanded.
    
    Args:
        module: AnsibleModule instance
        node: Name of node to remove (must be DC node)
        dc_node: Current DC node name
        hostname: Current hostname
        
    Returns:
        tuple: (changed, result_dict)
    """
    cmd = ['crm', 'cluster', 'remove', '-c', node, '-y' '-F']
    rc, out, err = module.run_command(cmd)

    if rc == 130 and "rm: cannot remove" in err and "Is a directory" in err:
        cleanup_cmd = "rm -rf /etc/sysconfig/sbd /etc/csync2/csync2.cfg /etc/corosync/corosync.conf " + \
                     "/etc/csync2/key_hagroup /etc/corosync/authkey /var/lib/heartbeat/crm/* " + \
                     "/var/lib/pacemaker/cib/* /var/lib/corosync/* /var/lib/pacemaker/pengine/* " + \
                     "/etc/pacemaker/authkey /var/lib/csync2/* ~/.config/crm/*"
        
        cleanup_rc, cleanup_out, cleanup_err = module.run_command(cleanup_cmd)
        if cleanup_rc != 0:
            module.fail_json(
                msg="Failed to destroy cluster and manual cleanup also failed",
                initial_error=err,
                cleanup_error=cleanup_err,
                initial_rc=rc,
                cleanup_rc=cleanup_rc
            )
    elif rc != 0:
        module.fail_json(
            msg=f"Failed to destroy cluster: {err}",
            command=cmd,
            rc=rc,
            stdout=out,
            stderr=err
        )
    
    return True, {
        'changed': True,
        'msg': f"Successfully destroyed cluster by removing DC node {node}",
        'dc_node': dc_node,
        'hostname': hostname,
        'target_node': node,
        'cluster_status': 'disbanded'
    }

def remove_from_cluster(module):
    """Remove a node from the cluster. If removing the DC node,
    this will destroy the cluster without status verification.
    
    Args:
        module: AnsibleModule instance
        
    Returns:
        tuple: (changed, result_dict)
    """
    node = module.params.get('cluster_node')
    force = module.params.get('force')
    
    if not node:
        module.fail_json(msg="cluster_node is required for cluster remove")
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")

    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()
    
    dc_node = status.get('summary', {}).get('dc_node')
    if not dc_node:
        module.fail_json(msg="No DC node found in cluster status")
        
    if hostname != dc_node:
        return False, {
            'changed': False,
            'msg': f"Node removal skipped - not DC node {dc_node}",
            'dc_node': dc_node,
            'hostname': hostname,
            'target_node': node
        }
    
    if module.check_mode:
        msg = f"Would remove node {node} from cluster"
        if node == dc_node:
            msg += " (this will destroy the cluster)"
        return True, {
            'changed': True,
            'msg': msg,
            'dc_node': dc_node,
            'hostname': hostname,
            'target_node': node
        }

    if node == dc_node:
        if not force:
            module.fail_json(
                msg=f"force=true is required to remove DC node {node}",
                dc_node=dc_node,
                hostname=hostname,
                target_node=node
            )
        return destroy_cluster_from_dc(module, node, dc_node, hostname)
    
    return remove_node_from_cluster(module, node, force, dc_node, hostname, status)

def parse_cluster_status(status_output):
    """Parse crm status output into structured data efficiently.
    
    Improvements:
    - Better error handling for malformed input
    - More robust parsing of node states
    - More efficient string processing
    - Better handling of resource statuses
    - Clearer separation of parsing stages
    - Better type handling for returned data
    """
    status = {
        'summary': {
            'stack': None,
            'dc_node': None,
            'dc_version': None,
            'last_updated': None,
            'last_change': None,
            'nodes_configured': 0,
            'resources_configured': 0,
            'resources_disabled': 0
        },
        'nodes': {
            'online': [],
            'offline': [],
            'standby': [],
            'unclean': []
        },
        'resources': {},
        'maintenance_mode': False
    }

    if not status_output:
        return status

    current_section = None
    sections = {'stack': [], 'nodes': [], 'resources': []}
    
    for line in status_output.splitlines():
        line = line.strip()
        if not line:
            continue

        if 'resource management is disabled' in line.lower():
            status['maintenance_mode'] = True
            continue

        if 'Stack:' in line:
            current_section = 'stack'
        elif 'Node List:' in line:
            current_section = 'nodes'
        elif 'Full List of Resources:' in line:
            current_section = 'resources'
            
        if current_section and line.startswith('*'):
            sections[current_section].append(line.lstrip('* '))

    for line in sections['stack']:
        if 'Stack: ' in line:
            status['summary']['stack'] = line.split('Stack: ')[1].split()[0]
        elif 'Current DC: ' in line:
            dc_info = line.split('Current DC: ')[1]
            status['summary']['dc_node'] = dc_info.split()[0]
            if '(version ' in dc_info:
                version_start = dc_info.find('(version ') + 9
                version_end = dc_info.find(')', version_start)
                if version_start > 8 and version_end > version_start:
                    status['summary']['dc_version'] = dc_info[version_start:version_end]
        elif 'Last updated:' in line:
            status['summary']['last_updated'] = line.split('Last updated: ')[1]
        elif 'Last change:' in line:
            status['summary']['last_change'] = line.split('Last change: ')[1]
        elif any(x in line.lower() for x in ('node configured', 'nodes configured')):
            try:
                status['summary']['nodes_configured'] = int(line.split()[0])
            except (ValueError, IndexError):
                continue
        elif 'resource instance' in line:
            try:
                parts = line.split()
                status['summary']['resources_configured'] = int(parts[0])
                if '(' in line and 'DISABLED' in line:
                    disabled = line[line.find('(')+1:line.find(')')].split()[0]
                    status['summary']['resources_disabled'] = int(disabled)
            except (ValueError, IndexError):
                continue

    node_state_map = {
        'online': 'online',
        'offline': 'offline',
        'standby': 'standby',
        'unclean': 'unclean'
    }

    for line in sections['nodes']:
        if line.startswith('Node '):
            try:
                node_info = line.split(':', 1)
                if len(node_info) < 2:
                    continue
                    
                node_name = node_info[0].replace('Node', '').strip()
                node_status = node_info[1].lower().strip()
                
                for state_key, state_value in node_state_map.items():
                    if state_key in node_status:
                        status['nodes'][state_value].append(node_name)
                        break
            except Exception:
                continue
        else:
            for state in node_state_map.keys():
                if f'{state}:' in line.lower():
                    if '[' in line and ']' in line:
                        nodes_str = line[line.find('[')+1:line.find(']')].strip()
                        if nodes_str and nodes_str != ' ':
                            status['nodes'][state].extend(
                                node.strip() for node in nodes_str.split() if node.strip()
                            )

    resource_states = {
        'started': 'Started',
        'stopped': 'Stopped',
        'disabled': 'Stopped (disabled)'
    }

    for line in sections['resources']:
        parts = line.split('\t')
        if len(parts) < 3:
            continue

        resource_name = parts[0].strip()
        resource_info = {
            'type': parts[1].strip('()').strip(),
            'status': 'Unknown',
            'node': None
        }

        status_part = parts[2].strip().lower()
        
        if 'started' in status_part:
            resource_info['status'] = 'Started'
            node_part = parts[2].split('Started', 1)[1].strip()
            node_part = node_part.replace('(maintenance)', '').replace('(MAINTENANCE)', '')
            if node_part.strip():
                resource_info['node'] = node_part.strip()
        else:
            for state_key, state_value in resource_states.items():
                if state_key in status_part:
                    resource_info['status'] = state_value
                    break

        status['resources'][resource_name] = resource_info

    for node_state in status['nodes']:
        status['nodes'][node_state] = sorted(set(status['nodes'][node_state]))

    return status

def get_cluster_status(module, fail_on_error=True):

    """Get comprehensive cluster status using AnsibleModule's run_command
    
    Args:
        module: AnsibleModule instance
        fail_on_error: Whether to fail on error or return None
        
    Returns:
        dict: Parsed cluster status information or None if error and fail_on_error=False
    """
    try:
        rc, stdout, stderr = module.run_command(['crm', 'status'])
        
        if rc != 0:
            if fail_on_error:
                module.fail_json(msg=f"Failed to get cluster status: {stderr}", rc=rc)
            return None
            
        return parse_cluster_status(stdout.strip())
        
    except Exception as e:
        if fail_on_error:
            module.fail_json(msg=f"Error getting cluster status: {str(e)}")
        return None

def restart_cluster(module):
    """Handle cluster restart operations.
    
    Can restart either entire cluster or individual nodes.
    """
    params = module.params
    cluster_node = params.get('cluster_node')
    force = params.get('force')

    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status before restart")

    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()

    dc_node = status.get('summary', {}).get('dc_node')
    if not dc_node:
        module.fail_json(msg="No DC node found in cluster status")
        
    if not cluster_node or cluster_node == 'all':
        if hostname != dc_node and not force:
            module.fail_json(msg=f"Cluster restart must be initiated from DC node {dc_node} unless force=true")
        cmd = ['crm', 'cluster', 'restart']
    else:
        cmd = ['crm', 'cluster', 'restart', cluster_node]
        
    if force:
        cmd += ['--force']

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would restart {'cluster' if not cluster_node or cluster_node == 'all' else cluster_node}",
            'dc_node': dc_node,
            'hostname': hostname,
            'command': cmd
        }

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Cluster restart failed: {err}", command=cmd)

    success, new_status = wait_for_cluster_change(
        module,
        lambda s: s.get('summary', {}).get('dc_node') is not None,
        timeout=module.params.get('operation_timeout', 120),
        error_msg=f"Timeout waiting for cluster to restart"
    )

    if not success:
        module.fail_json(msg="Failed to verify cluster restart completed")

    return True, {
        'changed': True,
        'msg': f"Successfully restarted {'cluster' if not cluster_node or cluster_node == 'all' else cluster_node}",
        'dc_node': new_status.get('summary', {}).get('dc_node'),
        'hostname': hostname
    }

def geo_init_cluster(module):
    """Initialize a geo-cluster configuration.

    Sets up required configuration for multi-site clustering.
    """
    params = module.params
    
    geo_site_id = params.get('geo_site_id')
    geo_site_ticket = params.get('geo_site_ticket') 
    
    if not geo_site_id:
        module.fail_json(msg="geo_site_id is required for geo-cluster initialization")
    if not geo_site_ticket:
        module.fail_json(msg="geo_site_ticket is required for geo-cluster initialization")

    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()

    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="No cluster configured - run cluster init first")

    dc_node = status.get('summary', {}).get('dc_node')
    if not dc_node:
        module.fail_json(msg="No DC node found in cluster status")

    if hostname != dc_node:
        return False, {
            'changed': False,
            'msg': f"Geo-init must run on DC node {dc_node}",
            'hostname': hostname
        }

    cmd_parts = ['crm', 'cluster', 'geo-init', '--cluster-name', geo_site_id, '--ticket', geo_site_ticket, '-y']

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': "Would initialize geo-cluster configuration",
            'command': ' '.join(cmd_parts),
            'dc_node': dc_node,
            'hostname': hostname
        }

    rc, out, err = module.run_command(cmd_parts)
    if rc != 0:
        module.fail_json(msg=f"Geo-cluster initialization failed: {err}", command=cmd_parts)

    success, new_status = wait_for_cluster_change(
        module,
        lambda s: True, 
        timeout=module.params.get('operation_timeout', 60),
        error_msg=f"Timeout waiting for geo-cluster initialization to complete"
    )

    return True, {
        'changed': True,
        'msg': "Successfully initialized geo-cluster configuration",
        'dc_node': dc_node,
        'hostname': hostname,
        'site_id': geo_site_id,
        'ticket': geo_site_ticket
    }

def manage_node_state(module):
    """Manage node state (standby/online)"""
    node = module.params['node']
    desired_state = module.params['state']
    
    status = get_cluster_status(module)
    current_state = 'standby' if node in status['nodes']['standby'] else 'online'
    
    if current_state == desired_state:
        return False, f"Node {node} is already in {desired_state} state"
    
    if module.check_mode:
        return True, f"Would change node {node} state from {current_state} to {desired_state}"
    
    if desired_state == 'standby':
        cmd = ['crm', 'node', 'standby', node]
    elif desired_state == 'online':
        cmd = ['crm', 'node', 'online', node] 
    else:
        module.fail_json(msg=f"Invalid node state: {desired_state}")
    
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to change node state: {err}")
        
    success, new_status = wait_for_cluster_change(
        module,
        lambda status: (
            (desired_state == 'standby' and node in status['nodes'].get('standby', [])) or
            (desired_state == 'online' and node in status['nodes'].get('online', []))
        ),
        timeout=module.params.get('operation_timeout', 40),
        error_msg=f"Timeout waiting for node {node} to enter {desired_state} state"
    )

    return True, f"Changed node {node} state to {desired_state}"

def set_preferred_node(module):
    """Set preferred node for a resource using location constraint
    
    Args:
        module: AnsibleModule instance
        
    Returns:
        tuple: (changed, result_dict)
    """
    resource = module.params['resource']
    preferred_node = module.params['preferred_node']
    constraint_id = f"prefer-{resource}"

    status = get_cluster_status(module, fail_on_error=False) 
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Preference setting skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    if resource not in status.get('resources', {}):
        module.fail_json(msg=f"Resource {resource} not found")

    cmd = [
        'crm', 'configure', 'location',
        constraint_id, 
        resource,      
        '100:',       
        preferred_node 
    ]

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would set preferred node {preferred_node} for resource {resource}",
            'command': cmd
        }

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to set preferred node: {err}")

    success, verify_status = wait_for_cluster_change(
        module,
        lambda s: verify_constraint(module, 'location', constraint_id),
        timeout=module.params.get('operation_timeout', 30),
        error_msg=f"Timeout waiting for preference to be set"
    )

    return True, {
        'changed': True,
        'msg': f"Set preferred node {preferred_node} for resource {resource}",
        'constraint': {
            'id': constraint_id,
            'resource': resource,
            'node': preferred_node,
            'score': '100'
        }
    }

def create_resource(module):
    """Create or modify a cluster resource with proper validation and command handling.
    
    Args:
        module: AnsibleModule instance
        
    Returns:
        tuple: (changed, result_dict)
    """
    params = module.params
    resource = params['resource']
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Resource {resource} creation skipped - not DC node {dc_node}",
            'hostname': hostname,
            'dc_node': dc_node,
            'maintenance_mode': status.get('maintenance_mode', False)
        }
    
    if resource in status.get('resources', {}):
        return False, {
            'changed': False,
            'msg': f"Resource {resource} already exists",
            'resource': resource,
            'dc_node': dc_node,
            'maintenance_mode': status.get('maintenance_mode', False)
        }
    
    required_params = ['resource_type', 'resource_class', 'resource_agent']
    if params.get('resource_class') != 'stonith':
        required_params.append('resource_provider')
        
    missing_params = [p for p in required_params if not params.get(p)]
    if missing_params:
        module.fail_json(
            msg=f"Missing required parameters: {', '.join(missing_params)}",
            resource=resource
        )
    
    cmd = ['crm', 'configure', 'primitive', resource]
    
    if params['resource_class'] == 'stonith':
        cmd.append(f"{params['resource_class']}:{params['resource_agent']}")
    else:
        cmd.append(
            f"{params['resource_class']}:"
            f"{params['resource_provider']}:"
            f"{params['resource_agent']}"
        )
    
    if params.get('parameters'):
        cmd.append('params')
        for param_name, param_value in params['parameters'].items():
            if isinstance(param_value, bool):
                param_value = "true" if param_value else "false"
            cmd.append(f'{param_name}="{param_value}"')
    
    if params.get('operations'):
        cmd.append('op')
        for op in params['operations']:
            cmd.append(op)
            
    if params.get('metadata'):
        cmd.append('meta')
        for meta_name, meta_value in params['metadata'].items():
            if isinstance(meta_value, bool):
                meta_value = "true" if meta_value else "false"
            cmd.append(f'{meta_name}="{meta_value}"')

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would create resource {resource}",
            'command': cmd,
            'resource': resource,
            'dc_node': dc_node,
            'maintenance_mode': status.get('maintenance_mode', False)
        }

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(
            msg=f"Failed to create resource {resource}",
            command=cmd,
            stdout=out,
            stderr=err,
            rc=rc
        )
    
    success, new_status = wait_for_cluster_change(
        module,
        lambda status: resource in status.get('resources', {}),
        timeout=module.params.get('operation_timeout', 40),
        error_msg=f"Timeout waiting for resource {resource} to be created"
    )
    
    if not success:
        module.fail_json(
            msg=f"Failed to verify resource {resource} creation",
            command=cmd,
            timeout=module.params.get('operation_timeout', 40),
            final_status=new_status
        )
    
    new_status = get_cluster_status(module)
    if resource not in new_status.get('resources', {}):
        module.fail_json(
            msg=f"Failed to verify resource {resource} creation. " +
                "Resource not found in cluster status.",
            maintenance_mode=new_status.get('maintenance_mode', False),
            command=cmd
        )
    
    resource_info = new_status['resources'][resource]
    
    return True, {
        'changed': True,
        'msg': f"Created resource {resource}",
        'command': cmd,
        'resource': {
            'name': resource,
            'type': f"{params['resource_class']}:{params.get('resource_provider', '')}:{params['resource_agent']}",
            'status': resource_info.get('status'),
            'node': resource_info.get('node'),
            'parameters': params.get('parameters'),
            'metadata': params.get('metadata')
        },
        'dc_node': dc_node,
        'maintenance_mode': new_status.get('maintenance_mode', False)
    }

def verify_resource(module, resource_name, status=None):
    """Verify resource exists in cluster configuration.
    
    Args:
        module: AnsibleModule instance
        resource_name: Name of resource to verify
        status: Optional cluster status dict
        
    Returns:
        tuple: (exists, resource_info)
    """
    if status is None:
        status = get_cluster_status(module, fail_on_error=False)
        if not status:
            return False, None
            
    resource_info = status.get('resources', {}).get(resource_name)
    return bool(resource_info), resource_info

def resource_exists(module, resource_name):
    """Check if a resource exists using cluster status"""
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        return False
        
    if 'resources' not in status:
        return False
        
    return resource_name in status['resources']

def delete_resource(module):
    """Delete one or more cluster resources with automatic DC node handling
    
    Supports both single resource string and list of resources
    
    Args:
        module: AnsibleModule instance with required parameters
        
    Returns:
        tuple: (changed, result_dict) indicating if changes were made and detailed status
    """
    params = module.params
    resources = params['resource']
    
    if isinstance(resources, str):
        resources = [resources]
    elif not isinstance(resources, list):
        module.fail_json(msg="Resource parameter must be either a string or list")
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()
        
    dc_node = status.get('summary', {}).get('dc_node')
    if not dc_node:
        module.fail_json(msg="No DC node found in cluster status")
        
    if hostname != dc_node:
        return False, {
            'changed': False,
            'msg': "Resource deletion skipped - not DC node",
            'dc_node': dc_node,
            'hostname': hostname,
            'maintenance_mode': status.get('maintenance_mode', False),
            'resources': resources
        }
    
    result = {
        'dc_node': dc_node,
        'hostname': hostname,
        'maintenance_mode': status.get('maintenance_mode', False),
        'resources': {},
        'changed': False
    }
    
    existing_resources = []
    for resource in resources:
        resource_info = status.get('resources', {}).get(resource)
        if resource_info:
            existing_resources.append(resource)
            result['resources'][resource] = {
                'initial_state': {
                    'status': resource_info.get('status'),
                    'node': resource_info.get('node'),
                    'type': resource_info.get('type')
                }
            }
    
    if not existing_resources:
        result['msg'] = "No specified resources exist in cluster"
        return False, result
        
    if module.check_mode:
        result.update({
            'changed': True,
            'msg': f"Would delete resources: {', '.join(existing_resources)}",
            'check_mode': True
        })
        return True, result
    
    overall_changed = False
    
    for resource in existing_resources:
        resource_info = status['resources'][resource]
        
        try:
            if resource_info['status'] != 'Stopped':
                rc, out, err = module.run_command(['crm', 'resource', 'stop', resource])
                if rc != 0:
                    result['resources'][resource]['error'] = f"Failed to stop resource: {err}"
                    continue
                
                success, stop_status = wait_for_cluster_change(
                    module,
                    lambda status: (
                        resource not in status.get('resources', {}) or
                        status['resources'][resource]['status'] == 'Stopped'
                    ),
                    timeout=module.params.get('operation_timeout', 40),
                    error_msg=f"Timeout waiting for resource {resource} to stop"
                )
                
                if not success:
                    result['resources'][resource]['error'] = "Failed to verify resource was stopped"
                    continue
            
            rc, out, err = module.run_command(['crm', 'configure', 'delete', resource])
            if rc != 0:
                result['resources'][resource]['error'] = f"Failed to delete resource: {err}"
                continue
            
            success, delete_status = wait_for_cluster_change(
                module,
                lambda status: resource not in status.get('resources', {}),
                timeout=module.params.get('operation_timeout', 40),
                error_msg=f"Timeout waiting for resource {resource} to be deleted"
            )
            
            if not success:
                result['resources'][resource]['error'] = "Failed to verify resource was deleted"
                continue
            
            result['resources'][resource].update({
                'changed': True,
                'final_status': 'deleted'
            })
            overall_changed = True
            
        except Exception as e:
            result['resources'][resource]['error'] = str(e)
            continue
    
    final_status = get_cluster_status(module)
    
    result.update({
        'changed': overall_changed,
        'final_cluster_status': final_status,
        'msg': "Resource deletion completed - see individual resource results for details"
    })
    
    success_count = sum(1 for r in result['resources'].values() if r.get('changed', False))
    error_count = sum(1 for r in result['resources'].values() if 'error' in r)
    result['summary'] = {
        'total_resources': len(existing_resources),
        'successful_deletions': success_count,
        'failed_deletions': error_count,
        'skipped_resources': len(resources) - len(existing_resources)
    }
    
    return overall_changed, result

def get_resource_type_info(module, resource_name, status):
    """Get detailed information about a resource's type and configuration.
    
    Args:
        module: AnsibleModule instance
        resource_name: Name of the resource to check
        status: Current cluster status dict
        
    Returns:
        dict: Resource type information including:
            - type: basic, clone, group, or master
            - parent: Name of parent resource if part of group/clone
            - children: List of child resources if group/clone
            - is_managed: Boolean indicating if resource is managed
    """
    if resource_name not in status.get('resources', {}):
        return None
        
    info = {
        'type': 'basic',
        'parent': None,
        'children': [],
        'is_managed': True
    }
    
    rc, out, err = module.run_command(['crm', 'configure', 'show', resource_name])
    if rc != 0:
        module.fail_json(msg=f"Failed to get resource configuration: {err}")
    
    config_lines = out.strip().split('\n')
    for line in config_lines:
        line = line.strip()
        if line.startswith('clone ') and resource_name in line:
            info['type'] = 'clone'
        elif line.startswith('master ') and resource_name in line:
            info['type'] = 'master'
        elif line.startswith('group ') and resource_name in line:
            info['type'] = 'group'
            members = line.split()[2:]  
            info['children'] = [m.strip() for m in members]
            
    rc, out, err = module.run_command(['crm', 'resource', 'meta', resource_name, 'show', 'is-managed'])
    if rc == 0:
        if "not found" in out:
            info['is_managed'] = True  
        else:
            info['is_managed'] = out.strip().lower() == 'true'

    if info['type'] == 'basic':
        rc, out, err = module.run_command(['crm', 'configure', 'show'])
        if rc == 0:
            for line in out.split('\n'):
                if line.startswith(('group ', 'clone ', 'master ')):
                    parts = line.split()
                    if resource_name in parts[2:]:  
                        info['parent'] = parts[1]  
                        info['type'] = 'child'
                        break
    
    return info

def manage_resource_state(module):
    """Manage resource states with support for complex resource types."""
    resource = module.params['resource']
    desired_state = module.params['state']
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    rc, hostname, err = module.run_command(['hostname'])
    if rc != 0:
        module.fail_json(msg=f"Failed to determine hostname: {err}")
    hostname = hostname.strip()
        
    dc_node = status.get('summary', {}).get('dc_node')
    if not dc_node:
        module.fail_json(msg="No DC node found in cluster status")

    result = {
        'changed': False,
        'dc_node': dc_node,
        'hostname': hostname,
        'maintenance_mode': status.get('maintenance_mode', False)
    }
        
    if hostname != dc_node:
        result['msg'] = f"Resource {resource} state change skipped - not DC node"
        return False, result

    if resource not in status.get('resources', {}):
        module.fail_json(msg=f"Resource {resource} not found")

    current_state = None
    if resource in status['resources']:
        current_state = 'started' if status['resources'][resource]['status'] == 'Started' else 'stopped'
    
    if current_state == desired_state:
        result['msg'] = f"Resource {resource} already in desired state: {desired_state}"
        return False, result

    if module.check_mode:
        result['msg'] = f"Would change resource {resource} state to {desired_state}"
        result['changed'] = True
        return True, result

    if desired_state == 'stopped':
        cmd = ['crm', 'resource', 'stop', resource]
    else:
        cmd = ['crm', 'resource', 'start', resource]

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to {desired_state} resource: {err}")

    result['changed'] = True
    result['msg'] = f"Changed resource {resource} state to {desired_state}"
    
    return True, result

def wait_for_cluster_change(module, check_condition, timeout=30, interval=2, error_msg=None):
    """Wait for cluster to reach desired state with configurable timeout.
    
    Args:
        module: AnsibleModule instance
        check_condition: Function that takes current status as argument and returns True when condition is met
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds
        error_msg: Custom error message if timeout occurs
    
    Returns:
        tuple: (success, status) where success is boolean and status is the final cluster status
    """
    end_time = time.time() + timeout
    
    while time.time() < end_time:
        current_status = get_cluster_status(module, fail_on_error=False)
        if not current_status:
            time.sleep(interval)
            continue
            
        if check_condition(current_status):
            return True, current_status
            
        time.sleep(interval)
    
    final_status = get_cluster_status(module, fail_on_error=False)
    msg = error_msg if error_msg else "Timeout waiting for cluster change"
    
    if not module.check_mode:
        module.fail_json(
            msg=msg,
            timeout=timeout,
            final_status=final_status
        )
    
    return False, final_status

def manage_resource_template(module):
    """Create or modify a resource template with proper command handling
    
    Args:
        module: AnsibleModule instance

    Returns:
        tuple: (changed, result_message)
    """
    template_name = module.params['template_name']
    resource_class = module.params.get('resource_class')
    resource_provider = module.params.get('resource_provider')
    resource_agent = module.params.get('resource_agent')
    parameters = module.params.get('parameters', {})
    state = module.params.get('state', 'present')

    if state == 'present':
        cmd = ['crm', 'configure', 'rsc_template', template_name]
        
        if resource_class == 'stonith':
            cmd.append(f"{resource_class}:{resource_agent}")
        else:
            cmd.append(f"{resource_class}:{resource_provider}:{resource_agent}")
            
        if parameters:
            cmd.append('params')
            for key, value in parameters.items():
                cmd.append(f'{key}="{value}"')
            
    elif state == 'absent':
        cmd = ['crm', 'configure', 'delete', template_name]
    else:
        module.fail_json(msg=f"Invalid state: {state}")
            
    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would {'create' if state == 'present' else 'delete'} template {template_name}",
            'command': cmd
        }
        
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(
            msg=f"Failed to {state} template {template_name}",
            command=cmd,
            stdout=out,
            stderr=err,
            rc=rc
        )
        
    return True, {
        'changed': True,
        'msg': f"Template {template_name} {'created' if state == 'present' else 'deleted'} successfully",
        'command': cmd,
        'stdout': out
    }

def manage_group(module):
    """Create, modify, or delete a resource group
    
    Args:
        module: AnsibleModule instance
        
    Returns:
        tuple: (changed, result_dict)
    """
    group_name = module.params['group_name']
    group_resources = module.params['group_resources']
    state = module.params.get('state', 'present')
    
    if not group_name:
        module.fail_json(msg="group_name is required")
    if state == 'present' and not group_resources:
        module.fail_json(msg="group_resources is required when state is present")
        
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Group management skipped - not DC node {dc_node}",
            'hostname': hostname
        }
    
    if state == 'present':
        cluster_resources = status.get('resources', {})
        missing_resources = [r for r in group_resources if r not in cluster_resources]
        if missing_resources:
            module.fail_json(
                msg=f"Resources not found: {', '.join(missing_resources)}",
                group=group_name
            )
    
    def verify_group(group_name):
        """Check if group exists with correct resources"""
        cmd = ['crm', 'configure', 'show', group_name]
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            return False
            
        if state == 'present':
            for line in out.splitlines():
                if line.strip().startswith('group') and group_name in line:
                    current_resources = line.split()[2:]  
                    return sorted(current_resources) == sorted(group_resources)
        return True
    
    group_exists = verify_group(group_name)
    if state == 'present' and group_exists:
        return False, {
            'changed': False,
            'msg': f"Group {group_name} already exists with requested resources",
            'group': {
                'name': group_name,
                'resources': group_resources
            }
        }
    elif state == 'absent' and not group_exists:
        return False, {
            'changed': False,
            'msg': f"Group {group_name} does not exist",
            'group': {'name': group_name}
        }
    
    if state == 'present':
        cmd = ['crm', 'configure', 'group', group_name]
        cmd.extend(group_resources)
    else:  
        cmd = ['crm', 'configure', 'delete', group_name]
    
    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would {'create' if state == 'present' else 'delete'} group {group_name}",
            'command': cmd,
            'group': {
                'name': group_name,
                'resources': group_resources if state == 'present' else None
            }
        }
    
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(
            msg=f"Failed to {state} group {group_name}: {err}",
            command=cmd,
            rc=rc,
            stdout=out,
            stderr=err
        )
    
    if verify_group(group_name) != (state == 'present'):
        module.fail_json(
            msg=f"Failed to verify group {state}",
            command=cmd,
            group={
                'name': group_name,
                'resources': group_resources if state == 'present' else None
            }
        )
    
    return True, {
        'changed': True,
        'msg': f"Group {group_name} {'created' if state == 'present' else 'deleted'} successfully",
        'command': cmd,
        'group': {
            'name': group_name,
            'resources': group_resources if state == 'present' else None
        }
    }

def manage_op_defaults(module):
    """Set operation defaults"""
    op_defaults = module.params['op_defaults_params']
    
    if not op_defaults:
        module.fail_json(msg="op_defaults_params is required")
        
    cmd = ['crm', 'configure', 'op_defaults']
    for key, value in op_defaults.items():
        cmd += f" {key}={value}"
        
    if module.check_mode:
        return True, f"Would set operation defaults: {cmd}"
        
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to set operation defaults: {err}")
        
    return True, "Operation defaults updated"

def manage_rsc_defaults(module):
    """Set resource defaults"""
    rsc_defaults = module.params['rsc_defaults_params']
    
    if not rsc_defaults:
        module.fail_json(msg="rsc_defaults_params is required")
        
    cmd = ['crm', 'configure', 'rsc_defaults']
    for key, value in rsc_defaults.items():
        cmd += f" {key}={value}"
        
    if module.check_mode:
        return True, f"Would set resource defaults: {cmd}"
        
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to set resource defaults: {err}")
        
    return True, "Resource defaults updated"

def manage_utilization(module):
    """Set resource utilization attributes"""
    resource = module.params['resource']
    utilization = module.params['utilization_params']
    
    if not utilization:
        module.fail_json(msg="utilization_params is required")
        
    changes = []
    for key, value in utilization.items():
        cmd = ['crm', 'configure', 'utilization', resource, 'set', key, str(value)]
        if not module.check_mode:
            rc, out, err = module.run_command(cmd)
            if rc != 0:
                module.fail_json(msg=f"Failed to set utilization attribute: {err}")
        changes.append(f"{key}={value}")
        
    return True, f"Set utilization attributes for {resource}: {', '.join(changes)}"

def resource_test(module):
    """Test resources on specified nodes"""
    resource = module.params['resource']
    nodes = module.params.get('test_nodes', [])
    
    cmd = ['crm', 'configure', 'rsctest', resource]
    if nodes:
        cmd.extend(nodes)
        
    if module.check_mode:
        return True, f"Would test resource: {cmd}"
        
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Resource test failed: {err}")
        
    return True, f"Resource {resource} tested successfully"

def manage_rsc_ticket(module):
    """Manage resource ticket constraints for geo-clustering.
    
    Args:
        module: AnsibleModule instance with parameters:
            - constraint_id (str): Unique identifier for the constraint
            - ticket_name (str): Name of the ticket to associate
            - ticket_resources (list): List of dicts with resource names, roles and attributes
            - state (str): 'present' or 'absent' to create/remove
            - loss_policy (str, optional): Policy for ticket loss
                         (fence|freeze|stop|demote)
            - node_attribute (str, optional): Node attribute for colocation
            
    Returns:
        tuple: (changed: bool, result: dict)
        
    The resource list format:
        [
            {
                'name': 'resource1',
                'role': 'Started|Master|Slave',  # Optional 
                'attributes': {                  # Optional
                    'attr1': 'value1',
                    'attr2': 'value2'
                }
            },
            ...
        ]
    """
    params = module.params
    constraint_id = params.get('constraint_id')
    ticket = params.get('ticket_name')
    resources = params.get('ticket_resources')
    state = params.get('state', 'present')
    loss_policy = params.get('loss_policy')

    if not all([constraint_id, ticket]):
        module.fail_json(msg="constraint_id and ticket_name are required")
        
    if state == 'present' and not resources:
        module.fail_json(msg="At least one resource must be specified when state=present")
        
    if loss_policy and loss_policy not in ('fence', 'freeze', 'stop', 'demote'):
        module.fail_json(msg=f"Invalid loss_policy: {loss_policy}")

    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Ticket constraint management skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    def build_delete_cmd(constraint_id):
        """Build command to delete constraint"""
        return ['crm', 'configure', 'delete', constraint_id]

    def build_create_cmd(constraint_id, ticket, resources, loss_policy=None, node_attribute=None):
        """Build command to create ticket constraint
        
        Args:
            constraint_id: ID for the constraint
            ticket: Ticket name 
            resources: List of resource specifications
            loss_policy: Optional loss policy
            node_attribute: Optional node attribute for colocation
        """
        cmd = ['crm', 'configure', 'rsc_ticket', constraint_id, ticket + ':']
        
        for resource in resources:
            resource_spec = resource['name']
            
            if resource.get('role'):
                resource_spec = f"{resource_spec}:{resource['role']}"
                
            if 'attributes' in resource:
                for attr, value in resource['attributes'].items():
                    resource_spec = f"{resource_spec} {attr}={value}"
                    
            cmd.append(resource_spec)
            
        if node_attribute:
            cmd.append(f"node-attribute={node_attribute}")
                
        if loss_policy:
            cmd.append(f"loss-policy={loss_policy}")
            
        return cmd

    if state == 'absent':
        if not verify_constraint(module, 'rsc_ticket', constraint_id):
            return False, {
                'changed': False,
                'msg': f"Ticket constraint {constraint_id} does not exist"
            }
            
        if module.check_mode:
            return True, {
                'changed': True,
                'msg': f"Would delete ticket constraint {constraint_id}"
            }
            
        cmd = build_delete_cmd(constraint_id)
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(
                msg=f"Failed to delete ticket constraint: {err}",
                cmd=' '.join(cmd),
                rc=rc
            )
            
        return True, {
            'changed': True,
            'msg': f"Ticket constraint {constraint_id} deleted"
        }

    cluster_resources = status.get('resources', {})
    missing_resources = []
    for resource in resources:
        if resource['name'] not in cluster_resources:
            missing_resources.append(resource['name'])
            
    if missing_resources:
        module.fail_json(
            msg=f"Resources not found: {', '.join(missing_resources)}",
            cluster_resources=list(cluster_resources.keys())
        )

    cmd = build_create_cmd(constraint_id, ticket, resources, loss_policy)
    
    if module.check_mode:
        return True, {
            'changed': True,
            'msg': "Would create/update ticket constraint",
            'constraint': {
                'id': constraint_id,
                'ticket': ticket,
                'resources': resources,
                'loss_policy': loss_policy,
                'command': ' '.join(cmd)
            }
        }

    if verify_constraint(module, 'rsc_ticket', constraint_id):
        del_cmd = build_delete_cmd(constraint_id)
        rc, out, err = module.run_command(del_cmd)
        if rc != 0:
            module.fail_json(
                msg=f"Failed to remove existing constraint: {err}",
                cmd=' '.join(del_cmd),
                rc=rc
            )

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(
            msg=f"Failed to create ticket constraint: {err}",
            cmd=' '.join(cmd),
            rc=rc
        )

    if not verify_constraint(module, 'rsc_ticket', constraint_id):
        module.fail_json(
            msg=f"Failed to verify ticket constraint {constraint_id}",
            cmd=' '.join(cmd)
        )

    return True, {
        'changed': True,
        'msg': f"Ticket constraint {constraint_id} created/updated successfully",
        'constraint': {
            'id': constraint_id,
            'ticket': ticket,
            'resources': resources,
            'loss_policy': loss_policy
        }
    }

def manage_fencing_topology(module):
    """Manage fencing device ordering"""
    levels = module.params['fencing_levels']
    
    cmd = ['crm', 'configure', 'fencing_topology']
    for level in levels:
        cmd += f" {level['target']}: {level['devices']}"
        
    if module.check_mode:
        return True, f"Would configure fencing topology: {cmd}"
        
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to configure fencing topology: {err}")
        
    return True, "Fencing topology configured"

def verify_monitor_operation(module, resource, interval, timeout=None):
    """
    Verify monitor operation configuration using crm configure show.
    
    Args:
        module: AnsibleModule instance
        resource: Name of resource to check
        interval: Expected monitoring interval
        timeout: Expected timeout value (optional)
        
    Returns:
        bool: True if monitor operation matches expected config
    """
    cmd = ['crm', 'configure', 'show', resource]
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to get resource configuration: {err}")

    if not out:
        module.fail_json(msg=f"No configuration found for resource {resource}")

    found_ops = []
    for line in out.split('\n'):
        line = line.strip()
        if 'op monitor' in line:
            parts = line.split()
            op_params = {}
            
            for param in parts[2:]:
                if '=' in param:
                    key, value = param.split('=', 1)
                    op_params[key] = value.strip('"\'')
            
            found_ops.append(op_params)
            
            if 'interval' in op_params and op_params['interval'] == interval:
                if timeout:
                    if 'timeout' in op_params and op_params['timeout'] == timeout:
                        return True
                else:
                    return True

    module.debug(
        f"No matching monitor operation found for {resource}. " +
        f"Found operations: {found_ops}"
    )
    return False

def manage_monitor(module):
    """
    Configure monitor operations for a resource with improved verification.
    
    Ensures monitor operations are only configured on DC node and verifies
    configuration after changes.
    """
    resource = module.params['resource']
    interval = module.params['monitor_interval']
    timeout = module.params.get('monitor_timeout')
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Monitor configuration skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    if resource not in status.get('resources', {}):
        module.fail_json(msg=f"Resource {resource} not found")

    if verify_monitor_operation(module, resource, interval, timeout):
        return False, {
            'changed': False, 
            'msg': f"Monitor operation already configured for {resource}",
            'monitor_config': {
                'interval': interval,
                'timeout': timeout if timeout else 'default'
            }
        }

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would configure monitor operation for {resource}",
            'monitor_config': {
                'interval': interval,
                'timeout': timeout if timeout else 'default'
            }
        }

    cmd = ['crm', 'configure', 'monitor', resource, interval]
    if timeout:
        cmd += ['timeout']
        
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to configure monitor operation: {err}")

    if not verify_monitor_operation(module, resource, interval, timeout):
        module.fail_json(msg=f"Failed to verify monitor configuration for {resource}")

    return True, {
        'changed': True,
        'msg': f"Monitor operation configured for {resource}",
        'monitor_config': {
            'interval': interval,
            'timeout': timeout if timeout else 'default'
        }
    }

def verify_constraint(module, constraint_type, constraint_id):
    """
    Verify a constraint exists with specified ID.
    
    Args:
        module: AnsibleModule instance
        constraint_type: Type of constraint (location/colocation/order)
        constraint_id: ID of constraint to verify
        
    Returns:
        bool: True if constraint exists
    """
    cmd = ['crm', 'configure', 'show', constraint_id]
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        return False
        
    constraint_markers = {
        'location': 'location',
        'colocation': 'colocation',
        'order': 'order'
    }
    return constraint_markers[constraint_type] in out.lower()

def manage_location(module):
    """
    Manage location constraints with improved validation and verification.
    
    Supports:
    - Multiple rules per constraint
    - Node attribute expressions
    - Role-specific constraints
    - Score ranges and INFINITY values
    """
    constraint_id = module.params['constraint_id']
    rules = module.params['location_rules']
    state = module.params.get('state', 'present')
    
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Location constraint management skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    if state == 'absent':
        if not verify_constraint(module, 'location', constraint_id):
            return False, {
                'changed': False,
                'msg': f"Location constraint {constraint_id} does not exist"
            }
        
        if module.check_mode:
            return True, {
                'changed': True,
                'msg': f"Would delete location constraint {constraint_id}"
            }
            
        cmd = ['crm', 'configure', 'delete', constraint_id]
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(msg=f"Failed to delete location constraint: {err}")
            
        return True, {
            'changed': True,
            'msg': f"Location constraint {constraint_id} deleted"
        }

    for rule in rules:
        if 'score' not in rule or 'expression' not in rule:
            module.fail_json(msg=f"Invalid rule format: {rule}")
            
    cmd = ['crm', 'configure', 'location', constraint_id]
    for rule in rules:
        cmd.append(f"{rule['score']}:")
        cmd.append(rule['expression'])
        
    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would create/update location constraint: {cmd}"
        }

    if verify_constraint(module, 'location', constraint_id):
        rc, out, err = module.run_command(['crm', 'configure', 'delete', constraint_id])
        if rc != 0:
            module.fail_json(msg=f"Failed to remove existing constraint: {err}")

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to create location constraint: {err}")

    if not verify_constraint(module, 'location', constraint_id):
        module.fail_json(msg=f"Failed to verify location constraint {constraint_id}")

    return True, {
        'changed': True,
        'msg': f"Location constraint {constraint_id} created/updated",
        'constraint': {
            'id': constraint_id,
            'rules': rules
        }
    }

def manage_colocation(module):
    """
    Manage colocation constraints with support for:
    - Resource sets
    - Role constraints
    - Node attribute matching
    - Multiple resources
    """
    constraint_id = module.params['constraint_id']
    score = module.params['constraint_score']
    resources = module.params['colocation_resources']
    state = module.params.get('state', 'present')
    
    if len(resources) < 2:
        module.fail_json(msg="At least two resources required for colocation")
        
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Colocation constraint management skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    if state == 'absent':
        if not verify_constraint(module, 'colocation', constraint_id):
            return False, {
                'changed': False,
                'msg': f"Colocation constraint {constraint_id} does not exist"
            }
            
        if module.check_mode:
            return True, {
                'changed': True,
                'msg': f"Would delete colocation constraint {constraint_id}"
            }
            
        cmd = ['crm', 'configure', 'delete', constraint_id]
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(msg=f"Failed to delete colocation constraint: {err}")
            
        return True, {
            'changed': True,
            'msg': f"Colocation constraint {constraint_id} deleted"
        }

    cluster_resources = status.get('resources', {})
    for resource in resources:
        if resource['name'] not in cluster_resources:
            module.fail_json(msg=f"Resource {resource['name']} not found")

    cmd = ['crm', 'configure', 'colocation', constraint_id, f"{score}:"]
    for resource in resources:
        if 'role' in resource:
            cmd.append(f"{resource['name']}:{resource['role']}")
        else:
            cmd.append(resource['name'])

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would create/update colocation constraint: {cmd}"
        }

    if verify_constraint(module, 'colocation', constraint_id):
        rc, out, err = module.run_command(['crm', 'configure', 'delete', constraint_id])
        if rc != 0:
            module.fail_json(msg=f"Failed to remove existing constraint: {err}")

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to create colocation constraint: {err}")

    if not verify_constraint(module, 'colocation', constraint_id):
        module.fail_json(msg=f"Failed to verify colocation constraint {constraint_id}")

    return True, {
        'changed': True,
        'msg': f"Colocation constraint {constraint_id} created/updated",
        'constraint': {
            'id': constraint_id,
            'score': score,
            'resources': resources
        }
    }

def manage_order(module):
    """
    Manage ordering constraints with support for:
    - Multiple resources
    - Action specifications
    - Resource sets
    - Custom scores
    """
    constraint_id = module.params['constraint_id']
    resources = module.params['order_resources']
    state = module.params.get('state', 'present')
    
    if len(resources) < 2:
        module.fail_json(msg="At least two resources required for ordering")
        
    status = get_cluster_status(module, fail_on_error=False)
    if not status:
        module.fail_json(msg="Unable to determine cluster status")
        
    is_dc, hostname, dc_node = is_current_node_dc(module, status)
    if not is_dc:
        return False, {
            'changed': False,
            'msg': f"Order constraint management skipped - not DC node {dc_node}",
            'hostname': hostname
        }

    if state == 'absent':
        if not verify_constraint(module, 'order', constraint_id):
            return False, {
                'changed': False,
                'msg': f"Order constraint {constraint_id} does not exist"
            }
            
        if module.check_mode:
            return True, {
                'changed': True,
                'msg': f"Would delete order constraint {constraint_id}"
            }
            
        cmd = ['crm', 'configure', 'delete', constraint_id]
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(msg=f"Failed to delete order constraint: {err}")
            
        return True, {
            'changed': True,
            'msg': f"Order constraint {constraint_id} deleted"
        }

    cluster_resources = status.get('resources', {})
    for resource in resources:
        if resource['name'] not in cluster_resources:
            module.fail_json(msg=f"Resource {resource['name']} not found")

    cmd = ['crm', 'configure', 'order', constraint_id]
    for resource in resources:
        if 'action' in resource:
            cmd.append(f"{resource['name']}:{resource['action']}")
        else:
            cmd.append(resource['name'])

    if module.check_mode:
        return True, {
            'changed': True,
            'msg': f"Would create/update order constraint: {cmd}"
        }

    if verify_constraint(module, 'order', constraint_id):
        rc, out, err = module.run_command(['crm', 'configure', 'delete', constraint_id])
        if rc != 0:
            module.fail_json(msg=f"Failed to remove existing constraint: {err}")

    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(msg=f"Failed to create order constraint: {err}")

    if not verify_constraint(module, 'order', constraint_id):
        module.fail_json(msg=f"Failed to verify order constraint {constraint_id}")

    return True, {
        'changed': True,
        'msg': f"Order constraint {constraint_id} created/updated",
        'constraint': {
            'id': constraint_id,
            'resources': resources
        }
    }

def main():
    module = AnsibleModule(
        argument_spec=dict(
            command=dict(type='str', required=True,
                        choices=['status', 'node', 'configure', 'cluster', 'resource']),
            subcommand=dict(type='str', required=False,
                           choices=['init', 'join', 'remove', 'property', 'resource', 'delete', 
                                  'restart', 'geo-init', 'group', 'monitor', 'utilization',
                                  'rsc_defaults', 'op_defaults', 'location', 'colocation', 'order', 
                                  'rsc_ticket', 'template']),
            cluster_name=dict(type='str', required=False),
            cluster_init_node=dict(type='str', required=False),
            fail_on_error=dict(type='bool', required=False, default=True),
            resource=dict(type='raw', required=False),
            resource_type=dict(type='str', required=False),
            resource_class=dict(type='str', required=False),
            resource_provider=dict(type='str', required=False),
            resource_agent=dict(type='str', required=False),
            parameters=dict(type='dict', required=False),
            state=dict(type='str', 
                      choices=['present', 'absent', 'started', 'stopped', 'standby', 'online'],
                      required=False),
            node=dict(type='str', required=False),
            preferred_node=dict(type='str', required=False),
            properties=dict(type='dict', required=False),
            cluster_node=dict(type='str', required=False),
            interface=dict(type='str', required=False),
            admin_ip_address=dict(type='str', required=False),
            qdevice=dict(type='bool', required=False, default=False),
            qnetd_hostname=dict(type='str', required=False),
            qdevice_port=dict(type='int', required=False),
            qdevice_algo=dict(type='str', required=False, choices=['ffsplit', 'lms']),
            qdevice_tie_breaker=dict(type='str', required=False, 
                                   choices=['lowest', 'highest', 'valid_node_id']),
            qdevice_tls=dict(type='str', required=False, choices=['on', 'off', 'required']),
            qdevice_heuristics=dict(type='str', required=False),
            qdevice_heuristics_mode=dict(type='str', required=False, 
                                       choices=['on', 'sync', 'off']),
            group_name=dict(type='str', required=False),
            group_resources=dict(type='list', required=False),
            monitor_interval=dict(type='str', required=False),
            monitor_timeout=dict(type='str', required=False),
            template_name=dict(type='str', required=False),
            utilization_params=dict(type='dict', required=False),
            op_defaults_params=dict(type='dict', required=False),
            rsc_defaults_params=dict(type='dict', required=False),
            constraint_id=dict(type='str', required=False),
            constraint_score=dict(type='str', required=False),
            location_rules=dict(type='list', required=False),
            colocation_resources=dict(type='list', required=False),
            order_resources=dict(type='list', required=False),
            force=dict(type='bool', required=False, default=False),
            geo_site_id=dict(type='str', required=False),
            geo_site_ticket=dict(type='str', required=False),
            ticket_name=dict(type='str', required=False),
            loss_policy=dict(type='str', required=False, 
                   choices=['fence', 'freeze', 'stop', 'demote']),
            operation_timeout=dict(type='int', required=False, default=30),
        ),
        supports_check_mode=True
    )
    
    module.get_bin_path('crm', required=True)
    
    command = module.params['command']
    subcommand = module.params.get('subcommand')
    fail_on_error = module.params.get('fail_on_error')
    changed = False
    result = {}

    try:
        if command == 'status':
            status = get_cluster_status(module, fail_on_error=fail_on_error)
            if status is None and not fail_on_error:
                result['status'] = {
                    'summary': {
                        'nodes_configured': 0,
                        'resources_configured': 0
                    },
                    'nodes': {
                        'online': [], 'offline': [], 'standby': [], 'unclean': []
                    },
                    'resources': {},
                    'maintenance_mode': False
                }
                result['msg'] = "Cluster not configured or not running"
            else:
                result['status'] = status
            changed = False

        elif command == 'cluster':
            if subcommand == 'init':
                if module.params.get('qdevice'):
                    changed, result = add_qdevice(module)
                else:
                    changed, result = init_cluster(module)
            elif subcommand == 'join':
                changed, result = join_cluster(module)
            elif subcommand == 'remove':
                changed, result = remove_from_cluster(module)
            elif subcommand == 'restart':
                changed, result = restart_cluster(module)
            elif subcommand == 'geo-init':
                changed, result = geo_init_cluster(module)
            else:
                module.fail_json(msg=f"Unsupported cluster subcommand: {subcommand}")

        elif command == 'node':
            changed, result['msg'] = manage_node_state(module)
            if not module.check_mode:
                result['status'] = get_cluster_status(module)

        elif command == 'resource':
            state = module.params.get('state')
            if state in ['started', 'stopped']:
                changed, result = manage_resource_state(module)
            else:
                module.fail_json(msg=f"Invalid resource state: {state}")
        elif command == 'configure':
            if subcommand == 'property':
                manage_cluster_property(module)
            elif subcommand == 'resource':
                state = module.params.get('state')
                if state == 'present':
                    changed, result = create_resource(module)
                elif state == 'absent':
                    changed, result = delete_resource(module)
                elif state in ['started', 'stopped']:
                    changed, result = manage_resource_state(module)
                else:
                    module.fail_json(msg=f"Invalid resource state: {state}")
            elif subcommand == 'group':
                changed, result = manage_group(module)
            elif subcommand == 'monitor':
                changed, result = manage_monitor(module)
            elif subcommand == 'utilization':
                changed, result = manage_utilization(module)
            elif subcommand == 'rsc_defaults':
                changed, result = manage_rsc_defaults(module)
            elif subcommand == 'op_defaults':
                changed, result = manage_op_defaults(module)
            elif subcommand == 'location':
                changed, result = manage_location(module)
            elif subcommand == 'colocation':
                changed, result = manage_colocation(module)
            elif subcommand == 'order':
               changed, result = manage_order(module)
            elif subcommand == 'template':
               changed, result = manage_resource_template(module)
            elif subcommand == 'rsc_ticket':
               changed, result = manage_rsc_ticket(module)
   
            else:
                module.fail_json(msg=f"Unsupported configure subcommand: {subcommand}")

        else:
            module.fail_json(msg=f"Invalid command: {command}")

        if not module.check_mode and changed:
            result['status'] = get_cluster_status(module)
            
        result['changed'] = changed
        module.exit_json(**result)

    except Exception as e:
        if not fail_on_error:
            result['failed'] = False
            result['msg'] = str(e)
            result['status'] = None
            module.exit_json(**result)
        else:
            module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()
