use bytes::{BytesMut, Buf};
use std::collections::HashMap;
use neighbor::Neighbor;


pub struct Neighbors {
	neighbrs: HashMap<String, Neighbor>,
	host_status_num: i32,
}

impl Neighbors {
	pub fn new() -> Neighbors {
		let neighbrs: HashMap<String, Neighbor> = HashMap::new();
		Neighbors {
			neighbrs,
			host_status_num: 0,
		}
	}

	pub fn insert_neighbor(&mut self, neighbr: Neighbor) {
		self.neighbrs.insert(neighbr.get_pub_key().clone(), neighbr);
	}

	fn delete_with_pub_key(&mut self, pub_key: &String) {
		self.neighbrs.remove(pub_key);
	}
	
	//To relevent may be removed later
	pub fn delete_neighbor(&mut self, neighbr: &Neighbor) {
		self.delete_with_pub_key(&neighbr.get_pub_key());
	}
	
	pub fn get_neighbor(&mut self, pub_key: &String) ->Option<&Neighbor> {
		self.neighbrs.get(pub_key)
	}
	
	pub fn get_host_status_num(&mut self) ->  i32 {
		self.host_status_num
	}
	
	pub fn set_host_status_num(&mut self, num: i32) {
		self.host_status_num = num;sss	
	}
	
	pub fn get_neighbors(&mut self) -> Vec<&Neighbor> {
		let neighbors: Vec<&Neighbor> = self.neighbrs
			.iter()
			.map(|(_, nbr)| nbr.clone()).collect();
		neighbors
	}

	///https://stackoverflow.com/questions/28909583/removing-entries-from-a-hashmap-based-on-value
	pub fn remove_inactive_neighbors(&mut self) {
		let empties: Vec<_> = self.neighbrs
			.iter()
			.filter(|&(_, ref value)| value.get_active() != self.host_status_num)
			.map(|(key, _)| key.clone())
			.collect();
		for empty in empties {
			self.delete_with_pub_key(&empty);
		}
	}
}




























