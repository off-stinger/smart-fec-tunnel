use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use smart_fec_tunnel::controller::{
    PlanAction, Planner, PortBinding, PortConflict, PortProbe, TransportProtocol,
};
use smart_fec_tunnel::product_config::{ProductConfig, Profile};
use std::io;
use std::net::{TcpListener, UdpSocket};

#[derive(Parser, Debug)]
#[command(version, about = "Smart Gateway read-only deployment planner")]
struct Cli {
    #[arg(long, value_enum, default_value_t = ProfileArg::Standard)]
    profile: ProfileArg,
    #[arg(long, default_value_t = 30)]
    bandwidth_mbps: u32,
    #[arg(long, default_value_t = 443)]
    tcp_port: u16,
    #[arg(long, default_value_t = 443)]
    udp_port: u16,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProfileArg {
    Standard,
    Enhanced,
    LowResource,
    Laboratory,
}

impl From<ProfileArg> for Profile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Standard => Self::Standard,
            ProfileArg::Enhanced => Self::Enhanced,
            ProfileArg::LowResource => Self::LowResource,
            ProfileArg::Laboratory => Self::Laboratory,
        }
    }
}

struct SocketProbe;

impl PortProbe for SocketProbe {
    fn conflict(&self, requested: &PortBinding) -> io::Result<Option<PortConflict>> {
        let address = (requested.address, requested.port);
        let result = match requested.protocol {
            TransportProtocol::Tcp => TcpListener::bind(address).map(drop),
            TransportProtocol::Udp => UdpSocket::bind(address).map(drop),
        };
        match result {
            Ok(()) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(Some(PortConflict {
                requested: requested.clone(),
                current_owner: None,
            })),
            Err(error) => Err(error),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = ProductConfig::for_profile(cli.profile.into());
    config.server.bandwidth_mbps = cli.bandwidth_mbps;
    config.server.public_tcp_port = cli.tcp_port;
    config.server.public_udp_port = cli.udp_port;

    let plan = Planner::new(&SocketProbe).build(&config)?;
    println!(
        "schema={} profile={:?}",
        plan.schema_version, config.profile
    );
    println!("modules={:?}", plan.modules);
    for action in &plan.actions {
        if let PlanAction::BindPort(binding) = action {
            println!(
                "bind={:?}/{:?}:{}",
                binding.protocol, binding.address, binding.port
            );
        }
    }
    if !plan.conflicts.is_empty() {
        for conflict in &plan.conflicts {
            eprintln!(
                "conflict={:?}/{:?}:{}",
                conflict.requested.protocol, conflict.requested.address, conflict.requested.port
            );
        }
        bail!(
            "deployment plan has {} port conflict(s)",
            plan.conflicts.len()
        );
    }
    println!("status=validated-plan-no-changes-applied");
    Ok(())
}
