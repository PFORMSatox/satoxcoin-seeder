use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::net::{NetAddr, Network, Service};
use crate::p2p::message::Address;
use crate::NODE_NETWORK;

const MIN_RETRY: i64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrStat {
    weight: f64,
    count: f64,
    pub reliability: f64,
}

impl AddrStat {
    pub fn new() -> Self {
        AddrStat {
            weight: 0.0,
            count: 0.0,
            reliability: 0.0,
        }
    }

    pub fn update(&mut self, good: bool, age: f64, tau: f64) {
        let f = (-age / tau).exp();
        self.reliability = self.reliability * f + if good { 1.0 - f } else { 0.0 };
        self.count = self.count * f + 1.0;
        self.weight = self.weight * f + (1.0 - f);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrInfo {
    pub service: Service,
    pub services: u64,
    pub last_try: i64,
    pub our_last_try: i64,
    pub our_last_success: i64,
    pub ignore_till: i64,
    pub stat_2h: AddrStat,
    pub stat_8h: AddrStat,
    pub stat_1d: AddrStat,
    pub stat_1w: AddrStat,
    pub stat_1m: AddrStat,
    pub client_version: i32,
    pub blocks: i32,
    pub total: i32,
    pub success: i32,
    pub client_sub_version: String,
    pub in_sync: bool,
}

impl AddrInfo {
    pub fn new(service: Service) -> Self {
        AddrInfo {
            service,
            services: NODE_NETWORK,
            last_try: 0,
            our_last_try: 0,
            our_last_success: 0,
            ignore_till: 0,
            stat_2h: AddrStat::new(),
            stat_8h: AddrStat::new(),
            stat_1d: AddrStat::new(),
            stat_1w: AddrStat::new(),
            stat_1m: AddrStat::new(),
            client_version: 0,
            blocks: 0,
            total: 0,
            success: 0,
            client_sub_version: String::new(),
            in_sync: false,
        }
    }

    pub fn update(&mut self, good: bool, now: i64) {
        if self.our_last_try == 0 {
            self.our_last_try = now - MIN_RETRY;
        }
        let age = (now - self.our_last_try) as f64;
        self.last_try = now;
        self.our_last_try = now;
        self.total += 1;
        if good {
            self.success += 1;
            self.our_last_success = now;
        }
        self.stat_2h.update(good, age, 3600.0 * 2.0);
        self.stat_8h.update(good, age, 3600.0 * 8.0);
        self.stat_1d.update(good, age, 3600.0 * 24.0);
        self.stat_1w.update(good, age, 3600.0 * 24.0 * 7.0);
        self.stat_1m.update(good, age, 3600.0 * 24.0 * 30.0);
        let ign = self.get_ignore_time();
        if ign > 0 && (self.ignore_till == 0 || self.ignore_till < ign + now) {
            self.ignore_till = ign + now;
        }
    }

    pub fn is_good(&self, wallet_port: u16, min_peer_proto_version: i32) -> bool {
        if self.service.port() != wallet_port {
            return false;
        }
        if self.services & NODE_NETWORK == 0 {
            return false;
        }
        if !self.service.is_routable() {
            return false;
        }
        if self.client_version > 0 && self.client_version < min_peer_proto_version {
            return false;
        }
        if !self.in_sync {
            return false;
        }
        if self.total <= 3 && self.success * 2 >= self.total {
            return true;
        }
        if self.stat_2h.reliability > 0.85 && self.stat_2h.count > 2.0 {
            return true;
        }
        if self.stat_8h.reliability > 0.70 && self.stat_8h.count > 4.0 {
            return true;
        }
        if self.stat_1d.reliability > 0.55 && self.stat_1d.count > 8.0 {
            return true;
        }
        if self.stat_1w.reliability > 0.45 && self.stat_1w.count > 16.0 {
            return true;
        }
        if self.stat_1m.reliability > 0.35 && self.stat_1m.count > 32.0 {
            return true;
        }
        false
    }

    pub fn get_ban_time(&self, min_peer_proto_version: i32) -> i64 {
        if self.client_version > 0 && self.client_version < min_peer_proto_version {
            return 604800;
        }
        if self.stat_1m.reliability - self.stat_1m.weight + 1.0 < 0.15 && self.stat_1m.count > 32.0 {
            return 30 * 86400;
        }
        if self.stat_1w.reliability - self.stat_1w.weight + 1.0 < 0.10 && self.stat_1w.count > 16.0 {
            return 7 * 86400;
        }
        if self.stat_1d.reliability - self.stat_1d.weight + 1.0 < 0.05 && self.stat_1d.count > 8.0 {
            return 1 * 86400;
        }
        0
    }

    pub fn get_ignore_time(&self) -> i64 {
        if self.stat_1m.reliability - self.stat_1m.weight + 1.0 < 0.20 && self.stat_1m.count > 2.0 {
            return 10 * 86400;
        }
        if self.stat_1w.reliability - self.stat_1w.weight + 1.0 < 0.16 && self.stat_1w.count > 2.0 {
            return 3 * 86400;
        }
        if self.stat_1d.reliability - self.stat_1d.weight + 1.0 < 0.12 && self.stat_1d.count > 2.0 {
            return 8 * 3600;
        }
        if self.stat_8h.reliability - self.stat_8h.weight + 1.0 < 0.08 && self.stat_8h.count > 2.0 {
            return 2 * 3600;
        }
        0
    }
}

#[derive(Debug, Clone)]
pub struct AddrReport {
    pub service: Service,
    pub client_version: i32,
    pub client_sub_version: String,
    pub blocks: i32,
    pub uptime: [f64; 5],
    pub last_success: i64,
    pub good: bool,
    pub services: u64,
}

#[derive(Debug, Default)]
pub struct AddrDbStats {
    pub n_banned: usize,
    pub n_avail: usize,
    pub n_tracked: usize,
    pub n_new: usize,
    pub n_good: usize,
    pub n_age: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResult {
    pub service: Service,
    pub services: u64,
    pub good: bool,
    pub ban_time: i64,
    pub height: i32,
    pub client_v: i32,
    pub client_sv: String,
    pub our_last_success: i64,
    pub in_sync: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddrDb {
    n_id: i32,
    id_to_info: HashMap<i32, AddrInfo>,
    ip_to_id: HashMap<Service, i32>,
    our_id: VecDeque<i32>,
    unk_id: HashSet<i32>,
    good_id: HashSet<i32>,
    pub banned: HashMap<Service, i64>,
    pub n_dirty: i32,
    pub wallet_port: u16,
    pub min_peer_proto_version: i32,
    pub force_ip: String,
}

impl AddrDb {
    pub fn new(wallet_port: u16, min_peer_proto_version: i32) -> Self {
        AddrDb {
            n_id: 0,
            id_to_info: HashMap::new(),
            ip_to_id: HashMap::new(),
            our_id: VecDeque::new(),
            unk_id: HashSet::new(),
            good_id: HashSet::new(),
            banned: HashMap::new(),
            n_dirty: 0,
            wallet_port,
            min_peer_proto_version,
            force_ip: String::from("a"),
        }
    }

    pub fn get_stats(&self) -> AddrDbStats {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        AddrDbStats {
            n_banned: self.banned.len(),
            n_avail: self.id_to_info.len(),
            n_tracked: self.our_id.len(),
            n_new: self.unk_id.len(),
            n_good: self.good_id.len(),
            n_age: self
                .our_id
                .front()
                .and_then(|id| self.id_to_info.get(id))
                .map(|info| now - info.our_last_try)
                .unwrap_or(0),
        }
    }

    pub fn restore_from(&mut self, saved: &AddrDb) {
        self.n_id = saved.n_id;
        self.id_to_info = saved.id_to_info.clone();
        self.ip_to_id = saved.ip_to_id.clone();
        self.our_id = saved.our_id.clone();
        self.unk_id = saved.unk_id.clone();
        self.good_id = saved.good_id.clone();
        self.banned = saved.banned.clone();
        self.n_dirty = saved.n_dirty;
    }

    pub fn id_to_info_len(&self) -> usize {
        self.id_to_info.len()
    }

    #[cfg(test)]
    pub fn add_raw_test(&mut self, service: Service, services: u64, time: u32, force: bool) {
        self.add_raw(service, services, time, force);
    }

    fn add_raw(&mut self, service: Service, services: u64, time: u32, force: bool) {
        if !force && !service.is_routable() {
            return;
        }
        if let Some(bantime) = self.banned.get(&service) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if force || (*bantime < now && (time as i64) > *bantime) {
                self.banned.remove(&service);
            } else {
                return;
            }
        }
        if let Some(&id) = self.ip_to_id.get(&service) {
            if let Some(info) = self.id_to_info.get_mut(&id) {
                if time > info.last_try as u32 {
                    info.last_try = time as i64;
                }
                if force {
                    info.ignore_till = 0;
                }
            }
            return;
        }
        let mut info = AddrInfo::new(service);
        info.services = services;
        info.last_try = time as i64;
        let id = self.n_id;
        self.n_id += 1;
        self.id_to_info.insert(id, info);
        self.ip_to_id.insert(service, id);
        self.unk_id.insert(id);
        self.n_dirty += 1;
    }

    pub fn add(&mut self, addr: &Address, force: bool) {
        let service = Service::new(addr.addr, addr.port);
        self.add_raw(service, addr.services, addr.time, force);
    }

    pub fn add_service(&mut self, service: Service, force: bool) {
        if !force && !service.is_routable() {
            return;
        }
        if self.ip_to_id.contains_key(&service) {
            return;
        }
        let info = AddrInfo::new(service);
        let id = self.n_id;
        self.n_id += 1;
        self.id_to_info.insert(id, info);
        self.ip_to_id.insert(service, id);
        self.unk_id.insert(id);
        self.n_dirty += 1;
    }

    #[cfg(test)]
    pub fn get_one_for_test(&mut self) -> Option<ServiceResult> {
        self.get_one()
    }

    pub fn get_many(&mut self, max: usize) -> Vec<ServiceResult> {
        let mut results = Vec::new();
        for _ in 0..max {
            match self.get_one() {
                Some(res) => results.push(res),
                None => break,
            }
        }
        results
    }

    fn get_one(&mut self) -> Option<ServiceResult> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let tot = self.unk_id.len() + self.our_id.len();
        if tot == 0 {
            return None;
        }
        for _ in 0..tot {
            let rnd = (rand::random::<u64>() as usize) % tot;
            let ret = if rnd < self.unk_id.len() {
                let it = *self.unk_id.iter().last()?;
                self.unk_id.remove(&it);
                it
            } else {
                let ret = *self.our_id.front()?;
                let info = self.id_to_info.get(&ret)?;
                if now - info.our_last_try < MIN_RETRY {
                    return None;
                }
                self.our_id.pop_front();
                ret
            };

            let info = self.id_to_info.get(&ret)?;
            if info.ignore_till > 0 && info.ignore_till < now {
                self.our_id.push_back(ret);
                if let Some(info) = self.id_to_info.get_mut(&ret) {
                    info.our_last_try = now;
                }
                continue;
            }
            self.n_dirty += 1;
            return Some(ServiceResult {
                service: info.service,
                services: info.services,
                good: false,
                ban_time: 0,
                height: 0,
                client_v: 0,
                client_sv: String::new(),
                our_last_success: info.our_last_success,
                in_sync: false,
            });
        }
        None
    }

    pub fn result_many(&mut self, results: &[ServiceResult]) {
        for res in results {
            if res.good {
                self.good_(res);
            } else {
                self.bad_(res);
            }
        }
    }

    fn good_(&mut self, res: &ServiceResult) {
        let id = self.lookup(res.service);
        if id < 0 {
            return;
        }
        self.unk_id.remove(&id);
        self.banned.remove(&res.service);
        if let Some(info) = self.id_to_info.get_mut(&id) {
            info.client_version = res.client_v;
            info.client_sub_version = res.client_sv.clone();
            info.blocks = res.height;
            info.in_sync = res.in_sync;
            info.services = res.services;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            info.update(true, now);
            if info.is_good(self.wallet_port, self.min_peer_proto_version) && !self.good_id.contains(&id) {
                self.good_id.insert(id);
            }
        }
        self.n_dirty += 1;
        self.our_id.push_back(id);
    }

    fn bad_(&mut self, res: &ServiceResult) {
        let id = self.lookup(res.service);
        if id < 0 {
            return;
        }
        self.unk_id.remove(&id);
        if let Some(info) = self.id_to_info.get_mut(&id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            info.update(false, now);
            let mut ban = res.ban_time;
            let ter = info.get_ban_time(self.min_peer_proto_version);
            if ter > 0 && ban < ter {
                ban = ter;
            }
            if ban > 0 {
                self.banned.insert(info.service, ban + now);
                self.ip_to_id.remove(&info.service);
                self.good_id.remove(&id);
                self.id_to_info.remove(&id);
            } else {
                if self.good_id.contains(&id) {
                    self.good_id.remove(&id);
                }
                self.our_id.push_back(id);
            }
        }
        self.n_dirty += 1;
    }

    fn lookup(&self, service: Service) -> i32 {
        self.ip_to_id.get(&service).copied().unwrap_or(-1)
    }

    pub fn get_ips(
        &self,
        requested_flags: u64,
        max: usize,
        nets: &[bool; 4],
    ) -> HashSet<NetAddr> {
        let mut ips = HashSet::new();
        if self.good_id.is_empty() {
            let id = self
                .our_id
                .front()
                .or_else(|| self.unk_id.iter().next());
            if let Some(&id) = id {
                if let Some(info) = self.id_to_info.get(&id) {
                    if info.services & requested_flags == requested_flags {
                        ips.insert(*info.service.addr());
                    }
                }
            }
            return ips;
        }
        let filtered: Vec<i32> = self
            .good_id
            .iter()
            .filter(|&&id| {
                self.id_to_info
                    .get(&id)
                    .map(|info| info.services & requested_flags == requested_flags)
                    .unwrap_or(false)
            })
            .copied()
            .collect();
        if filtered.is_empty() {
            return ips;
        }
        let count = std::cmp::min(max.max(1), filtered.len() / 2);
        let mut ids = HashSet::new();
        while ids.len() < count {
            ids.insert(filtered[(rand::random::<u64>() as usize) % filtered.len()]);
        }
        for &id in &ids {
            if let Some(info) = self.id_to_info.get(&id) {
                let net_idx = match info.service.network() {
                    Network::Ipv4 => 0,
                    Network::Ipv6 => 1,
                    Network::Tor => 2,
                    Network::I2p => 3,
                    Network::Unroutable => continue,
                };
                if net_idx < nets.len() && nets[net_idx] {
                    ips.insert(*info.service.addr());
                }
            }
        }
        ips
    }

    pub fn get_all(&self) -> Vec<AddrReport> {
        let mut reports = Vec::new();
        for &id in &self.our_id {
            if let Some(info) = self.id_to_info.get(&id) {
                if info.success > 0 {
                    reports.push(AddrReport {
                        service: info.service,
                        client_version: info.client_version,
                        client_sub_version: info.client_sub_version.clone(),
                        blocks: info.blocks,
                        uptime: [
                            info.stat_2h.reliability,
                            info.stat_8h.reliability,
                            info.stat_1d.reliability,
                            info.stat_1w.reliability,
                            info.stat_1m.reliability,
                        ],
                        last_success: info.our_last_success,
                        good: info.is_good(self.wallet_port, self.min_peer_proto_version),
                        services: info.services,
                    });
                }
            }
        }
        reports
    }

    pub fn reset_ignores(&mut self) {
        for info in self.id_to_info.values_mut() {
            info.ignore_till = 0;
        }
    }

    /// Snapshot good IPs for DNS responses (avoid holding lock)
    pub fn snapshot_good_ips(&self, max: usize) -> Vec<NetAddr> {
        let nets = [true, true, false, false];
        self.get_ips(0, max, &nets).into_iter().collect()
    }
}

pub type SharedDb = Arc<RwLock<AddrDb>>;

pub fn new_shared_db(wallet_port: u16, min_peer_proto_version: i32) -> SharedDb {
    Arc::new(RwLock::new(AddrDb::new(wallet_port, min_peer_proto_version)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_service(ip: &str, port: u16) -> Service {
        Service::new(NetAddr::from_str(ip).unwrap(), port)
    }

    fn make_addr(ip: &str, port: u16) -> Address {
        Address {
            time: 100000000,
            services: NODE_NETWORK,
            addr: NetAddr::from_str(ip).unwrap(),
            port,
        }
    }

    #[test]
    fn test_stat_update_good() {
        let mut s = AddrStat::new();
        s.update(true, 100.0, 7200.0);
        assert!(s.reliability > 0.0);
        assert!(s.count > 0.0);
    }

    #[test]
    fn test_stat_update_bad() {
        let mut s = AddrStat::new();
        s.update(false, 100.0, 7200.0);
        assert!(s.reliability < 0.01);
    }

    #[test]
    fn test_stat_decay() {
        let mut s = AddrStat::new();
        for _ in 0..10 { s.update(true, 1.0, 7200.0); }
        let r = s.reliability;
        for _ in 0..10 { s.update(false, 1.0, 7200.0); }
        assert!(s.reliability < r);
    }

    #[test]
    fn test_info_is_good_basic() {
        let mut info = AddrInfo::new(make_service("1.2.3.4", 60777));
        info.in_sync = true; info.services = NODE_NETWORK;
        info.success = 2; info.total = 3;
        assert!(info.is_good(60777, 70025));
    }

    #[test]
    fn test_info_wrong_port() {
        let mut info = AddrInfo::new(make_service("1.2.3.4", 60777));
        info.in_sync = true; info.services = NODE_NETWORK;
        info.success = 2; info.total = 3;
        assert!(!info.is_good(12345, 70025));
    }

    #[test]
    fn test_info_not_in_sync() {
        let mut info = AddrInfo::new(make_service("1.2.3.4", 60777));
        info.services = NODE_NETWORK;
        assert!(!info.is_good(60777, 70025));
    }

    #[test]
    fn test_db_add() {
        let mut db = AddrDb::new(60777, 70025);
        db.add(&make_addr("8.8.8.8", 60777), false);
        assert_eq!(db.get_stats().n_avail, 1);
    }

    #[test]
    fn test_db_duplicate() {
        let mut db = AddrDb::new(60777, 70025);
        let a = make_addr("8.8.8.8", 60777);
        db.add(&a, false); db.add(&a, false);
        assert_eq!(db.get_stats().n_avail, 1);
    }

    #[test]
    fn test_db_banned() {
        let mut db = AddrDb::new(60777, 70025);
        let s = make_service("1.2.3.4", 60777);
        db.banned.insert(s, i64::MAX);
        db.add(&make_addr("1.2.3.4", 60777), false);
        assert_eq!(db.get_stats().n_avail, 0);
    }

    #[test]
    fn test_db_get_many_empty() {
        assert!(AddrDb::new(60777, 70025).get_many(16).is_empty());
    }

    #[test]
    fn test_db_get_one() {
        let mut db = AddrDb::new(60777, 70025);
        db.add(&make_addr("8.8.8.8", 60777), false);
        let r = db.get_many(1);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].service.port(), 60777);
    }

    #[test]
    fn test_db_good_bad_cycle() {
        let mut db = AddrDb::new(60777, 70025);
        db.add(&make_addr("8.8.8.8", 60777), false);
        let mut r = db.get_many(1);
        assert_eq!(r.len(), 1);
        r[0].good = true; r[0].client_v = 70028;
        r[0].height = 1000000; r[0].in_sync = true;
        db.result_many(&r);
        assert_eq!(db.get_stats().n_good, 1);
        // Node goes to our_id with cooldown (MIN_RETRY=1000s)
        // Immediate re-fetch returns empty due to cooldown
        let r2 = db.get_many(1);
        assert!(r2.is_empty(), "cooldown prevents immediate re-fetch");
        assert_eq!(db.get_stats().n_good, 1);
    }

    #[test]
    fn test_get_ips() {
        let mut db = AddrDb::new(60777, 70025);
        for i in 1..=10 {
            db.add_service(make_service(&format!("{i}.{i}.{i}.{i}"), 60777), false);
        }
        for _ in 0..5 {
            let mut r = db.get_many(1);
            if !r.is_empty() {
                r[0].good = true; r[0].client_v = 70028;
                r[0].height = 1000000; r[0].in_sync = true;
                db.result_many(&r);
            }
        }
        let ips = db.get_ips(NODE_NETWORK, 100, &[true, true, false, false]);
        assert!(!ips.is_empty());
    }

    #[test]
    fn test_reset_ignores() {
        let mut db = AddrDb::new(60777, 70025);
        db.add_service(make_service("1.2.3.4", 60777), false);
        db.id_to_info.iter_mut().next().unwrap().1.ignore_till = 12345;
        db.reset_ignores();
        assert_eq!(db.id_to_info.iter().next().unwrap().1.ignore_till, 0);
    }

    #[test]
    fn test_get_ban_low_version() {
        let mut info = AddrInfo::new(make_service("1.2.3.4", 60777));
        info.client_version = 70000;
        assert_eq!(info.get_ban_time(70025), 604800);
    }

    #[test]
    fn test_snapshot() {
        let mut db = AddrDb::new(60777, 70025);
        for i in 1..=5 {
            db.add_service(make_service(&format!("{i}.{i}.{i}.{i}"), 60777), false);
        }
        for _ in 0..5 {
            let mut r = db.get_many(1);
            if !r.is_empty() {
                r[0].good = true; r[0].client_v = 70028;
                r[0].height = 1000000; r[0].in_sync = true;
                db.result_many(&r);
            }
        }
        assert!(!db.snapshot_good_ips(10).is_empty());
    }
}
