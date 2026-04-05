use eframe::egui;

struct Peer {
    name: &'static str,
    status: &'static str,
    reputation: f32,
}

pub fn show_peer_list(ui: &mut egui::Ui) {
    let peers = [
        Peer { name: "alex",      status: "online", reputation: 0.88 },
        Peer { name: "mira",      status: "online", reputation: 0.75 },
        Peer { name: "node_7f4a", status: "online", reputation: 0.12 },
        Peer { name: "p33r_x9",   status: "away",   reputation: 0.55 },
        Peer { name: "bootstrap1",status: "online", reputation: 0.95 },
    ];
}
