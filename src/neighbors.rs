use std::collections::HashMap;
use types::HelloData;
use base64::encode;
use std::net::SocketAddr;
use std::str;

pub struct Neighbor {
   pub pub_key: [u8;32],
   pub  pay_addr: String,
   pub  sock_addr: SocketAddr,
}

impl Neighbor {
    pub fn new(rtn_data: &HelloData) -> Neighbor {
        Neighbor {
            pub_key: rtn_data.pub_key.clone(),
            pay_addr: rtn_data.pay_addr.clone(), //should have the right address
            sock_addr: rtn_data.sock_addr,
        }
    }
}


pub struct Neighbors {
    neighbrs: HashMap<[u8;32], Neighbor>,
}

impl Neighbors {
    pub fn new() -> Neighbors {
        let neighbrs: HashMap<[u8;32], Neighbor> = HashMap::new();
        Neighbors { neighbrs }
    }

    pub fn insert_neighbor(&mut self, ngb: Neighbor ) {
        self.neighbrs.insert(ngb.pub_key.clone(), ngb);
    }

    pub fn add_neighbor(&mut self, rtn_data: &HelloData) {
        let ngb = Neighbor::new(&rtn_data);
        self.insert_neighbor(ngb);
    }

    fn remove_neighbor(&mut self, pub_key: &[u8]) {
        self.neighbrs.remove(pub_key);
    }

    pub fn get_neighbor(&mut self, pub_key: &[u8]) -> Option<&Neighbor> {
        self.neighbrs.get(pub_key)
    }

    pub fn get_neighbors(&mut self) -> Vec<&Neighbor> {
        let neighbors: Vec<&Neighbor> = self.neighbrs.iter().map(|(_, nbr)| nbr.clone()).collect();
        neighbors
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use dsocket::create_sockaddr;



    fn neighbor_one() -> Neighbor {
        let sock_addr = create_sockaddr(&format!("{}:{}","224.0.0.3","41235")).unwrap();
        let pay_addr = "Powe9023=".to_string();
        let pub_key = [23;32]; //Fake address

        Neighbor {
            pub_key,
            pay_addr, //should have the right address
            sock_addr
        }
    }

    fn neighbor_two() -> Neighbor {
        let sock_addr = create_sockaddr(&format!("{}:{}","224.0.0.7","51235")).unwrap();
        let pay_addr = "Powe9023=".to_string();
        let pub_key = [3;32]; //Fake address

        Neighbor {
            pub_key,
            pay_addr, //should have the right address
            sock_addr
        }
    }


    fn neighbor_three() -> Neighbor {
        let sock_addr = create_sockaddr(&format!("{}:{}","224.0.0.2","44235")).unwrap();
        let pay_addr = "Pouuwe9023=".to_string();
        let pub_key = [13;32]; //Fake address

        Neighbor {
            pub_key,
            pay_addr, //should have the right address
            sock_addr
        }
    }

    fn neighbor_four() -> Neighbor {
        let sock_addr = create_sockaddr(&format!("{}:{}","224.0.0.1","41295")).unwrap();
        let pay_addr = "PouuweHyD9023=".to_string();
        let pub_key = [22;32]; //Fake address

        Neighbor {
            pub_key,
            pay_addr, //should have the right address
            sock_addr
        }
    }

    fn given_neighbors() -> Neighbors {
        let mut ngbs = Neighbors::new();
        let ne_1 = neighbor_one();
        let ne_2 = neighbor_two();
        let ne_3 = neighbor_three();
        let ne_4 = neighbor_four();
        ngbs.insert_neighbor(ne_1);
        ngbs.insert_neighbor(ne_2);
        ngbs.insert_neighbor(ne_3);
        ngbs.insert_neighbor(ne_4);
        ngbs
    }


    #[test]
    fn neighbors_test_number_neighbors() {
        let mut ngbrs = given_neighbors();
        let  vec_neighbors = ngbrs.get_neighbors();
        assert_eq!(vec_neighbors.len(), 4);
    }

}