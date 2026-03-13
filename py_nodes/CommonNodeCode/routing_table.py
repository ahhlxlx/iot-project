from math import inf

class RouteEntry:
    def __init__(self, neighbor_id, avg_latency, rssi, power_cost):
        self.neighbor_id = neighbor_id
        self.avg_latency = avg_latency
        self.rssi = rssi
        self.power_cost = power_cost

class RoutingTable:
    MAX_NEIGHBOR = 10

    def __init__(self):
        self.entries = {}

    def update_route(self, neighbor_id, avg_latency, rssi, power_cost):
        self.entries[neighbor_id] = RouteEntry(neighbor_id,avg_latency,rssi,power_cost)

        if len(self.entries) > self.MAX_NEIGHBOR:
            oldest_key = next(iter(self.entries))
            del self.entries[oldest_key]

    def select_best_next_hop(self):
        if not self.entries:
            return 0xFF # No neighbors found
        
        best_neighbor = None
        best_cost = float(inf)
        
        for neighbor_id, entry in self.entries.items():
            # Cost = Latency + (PowerCost * 10)
            cost = entry.avg_latency + (entry.power_cost * 10)

            if cost < best_cost:
                best_cost = cost
                best_neighbor = neighbor_id
        return best_neighbor