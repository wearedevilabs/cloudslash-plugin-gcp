package gcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/storage/v1"

	pb "github.com/DrSkyle/cloudslash-plugin-sdk/shared/proto"
)

type collector struct {
	nodes    []*pb.Node
	edges    []*pb.Edge
	seen     map[string]bool
	edgeSeen map[string]bool
}

func newCollector() *collector {
	return &collector{seen: make(map[string]bool), edgeSeen: make(map[string]bool)}
}

func (c *collector) addNode(crn string, properties map[string]any) {
	if crn == "" || c.seen[crn] {
		return
	}
	c.seen[crn] = true
	c.nodes = append(c.nodes, &pb.Node{Crn: crn, Properties: encode(properties)})
}

func (c *collector) addEdge(source, target, kind string) {
	if source == "" || target == "" || source == target {
		return
	}
	key := source + "\x00" + target + "\x00" + kind
	if c.edgeSeen[key] {
		return
	}
	c.edgeSeen[key] = true
	c.edges = append(c.edges, &pb.Edge{SourceCrn: source, TargetCrn: target, Relation: kind})
}

func lastPath(value string) string {
	value = strings.TrimSuffix(value, "/")
	if index := strings.LastIndex(value, "/"); index >= 0 {
		return value[index+1:]
	}
	return value
}

// Collect reads the supported GCP resource families and returns normalized
// nodes and cross-resource relationships. Partial failures are returned as
// warnings so the engine can still analyze what was reachable.
func Collect(ctx context.Context, client *Client, project string, logger *slog.Logger) ([]*pb.Node, []*pb.Edge, []error) {
	c := newCollector()
	var errs []error
	warn := func(scanner string, err error) {
		if err != nil {
			logger.Warn("GCP scanner warning", "scanner", scanner, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", scanner, err))
		}
	}

	instanceCRNs := make(map[string]string)

	warn("ComputeInstances", client.Compute.Instances.AggregatedList(project).Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for scope, scoped := range page.Items {
			zone := strings.TrimPrefix(scope, "zones/")
			for _, instance := range scoped.Instances {
				instanceNode := crn(project, "compute", "instance", zone, instance.Name)
				instanceCRNs[instance.SelfLink] = instanceNode
				network, subnet := "", ""
				for _, nic := range instance.NetworkInterfaces {
					network, subnet = nic.Network, nic.Subnetwork
					break
				}
				c.addNode(instanceNode, map[string]any{
					"provider": "gcp", "project": project, "name": instance.Name,
					"zone": zone, "region": regionFromZone(zone), "status": instance.Status,
					"machine_type": lastPath(instance.MachineType), "labels": instance.Labels,
					"network": lastPath(network), "subnetwork": lastPath(subnet),
					"created_at": instance.CreationTimestamp,
				})
				if network != "" {
					c.addEdge(instanceNode, crn(project, "compute", "network", lastPath(network)), "AttachedTo")
				}
				if subnet != "" {
					c.addEdge(instanceNode, crn(project, "compute", "subnetwork", regionFromZone(zone), lastPath(subnet)), "AttachedTo")
				}
				for _, disk := range instance.Disks {
					if disk.Source != "" {
						c.addEdge(crn(project, "compute", "disk", zone, lastPath(disk.Source)), instanceNode, "AttachedTo")
					}
				}
			}
		}
		return nil
	}))

	warn("ComputeDisks", client.Compute.Disks.AggregatedList(project).Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for scope, scoped := range page.Items {
			zone := strings.TrimPrefix(scope, "zones/")
			for _, disk := range scoped.Disks {
				diskNode := crn(project, "compute", "disk", zone, disk.Name)
				c.addNode(diskNode, map[string]any{
					"provider": "gcp", "project": project, "name": disk.Name,
					"zone": zone, "region": regionFromZone(zone), "size_gb": disk.SizeGb,
					"status": disk.Status, "type": lastPath(disk.Type), "labels": disk.Labels,
				})
				for _, user := range disk.Users {
					if instanceCRN, ok := instanceCRNs[user]; ok {
						c.addEdge(diskNode, instanceCRN, "AttachedTo")
					}
				}
			}
		}
		return nil
	}))

	warn("ComputeAddresses", client.Compute.Addresses.AggregatedList(project).Pages(ctx, func(page *compute.AddressAggregatedList) error {
		for scope, scoped := range page.Items {
			region := strings.TrimPrefix(scope, "regions/")
			for _, address := range scoped.Addresses {
				addressNode := crn(project, "compute", "address", region, address.Name)
				c.addNode(addressNode, map[string]any{
					"provider": "gcp", "project": project, "name": address.Name,
					"region": region, "address": address.Address, "status": address.Status,
					"address_type": address.AddressType, "purpose": address.Purpose,
				})
				for _, user := range address.Users {
					if instanceCRN, ok := instanceCRNs[user]; ok {
						c.addEdge(addressNode, instanceCRN, "AttachedTo")
					}
				}
			}
		}
		return nil
	}))

	warn("ForwardingRules", client.Compute.ForwardingRules.AggregatedList(project).Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for scope, scoped := range page.Items {
			region := strings.TrimPrefix(scope, "regions/")
			for _, rule := range scoped.ForwardingRules {
				ruleNode := crn(project, "compute", "forwardingRule", region, rule.Name)
				c.addNode(ruleNode, map[string]any{
					"provider": "gcp", "project": project, "name": rule.Name,
					"region": region, "address": rule.IPAddress, "scheme": rule.LoadBalancingScheme,
					"target": lastPath(rule.Target), "backend_service": lastPath(rule.BackendService),
				})
				if target := instanceCRNs[rule.Target]; target != "" {
					c.addEdge(ruleNode, target, "FlowsTo")
				}
			}
		}
		return nil
	}))

	warn("Networks", client.Compute.Networks.List(project).Pages(ctx, func(page *compute.NetworkList) error {
		for _, network := range page.Items {
			networkNode := crn(project, "compute", "network", network.Name)
			c.addNode(networkNode, map[string]any{
				"provider": "gcp", "project": project, "name": network.Name,
				"auto_create_subnetworks": network.AutoCreateSubnetworks,
			})
		}
		return nil
	}))

	warn("Subnetworks", client.Compute.Subnetworks.AggregatedList(project).Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for scope, scoped := range page.Items {
			region := strings.TrimPrefix(scope, "regions/")
			for _, subnet := range scoped.Subnetworks {
				subnetNode := crn(project, "compute", "subnetwork", region, subnet.Name)
				c.addNode(subnetNode, map[string]any{
					"provider": "gcp", "project": project, "name": subnet.Name,
					"region": region, "network": lastPath(subnet.Network), "cidr": subnet.IpCidrRange,
				})
				if subnet.Network != "" {
					c.addEdge(subnetNode, crn(project, "compute", "network", lastPath(subnet.Network)), "AttachedTo")
				}
			}
		}
		return nil
	}))

	warn("StorageBuckets", client.Storage.Buckets.List(project).Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			bucketNode := crn(project, "storage", "bucket", bucket.Name)
			versioning := false
			if bucket.Versioning != nil {
				versioning = bucket.Versioning.Enabled
			}
			c.addNode(bucketNode, map[string]any{
				"provider": "gcp", "project": project, "name": bucket.Name,
				"location": bucket.Location, "storage_class": bucket.StorageClass,
				"versioning": versioning, "labels": bucket.Labels, "created_at": bucket.TimeCreated,
			})
		}
		return nil
	}))

	return c.nodes, c.edges, errs
}
