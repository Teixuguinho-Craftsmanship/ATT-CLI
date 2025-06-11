use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "attcli")]
#[command(about = "A CLI tool for browsing the MITRE ATT&CK Matrix")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all APT (Advanced Persistent Threat) groups
    #[command(name = "apt-list")]
    AptList,
    /// Show information about a specific APT group
    #[command(name = "apt")]
    Apt { name: String },
    /// Show information about a technique by ID (e.g., T1055)
    #[command(name = "tid")]
    TechniqueId { id: String },
    /// Show information about a technique by name
    #[command(name = "tn")]
    TechniqueName { name: String },
    /// Show information about a tactic (e.g., persistence, privilege-escalation)
    #[command(name = "tactic")]
    Tactic { name: String },
}

#[derive(Debug, Deserialize, Serialize)]
struct AttackData {
    objects: Vec<AttackObject>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttackObject {
    #[serde(rename = "type")]
    obj_type: String,
    id: String,
    name: Option<String>,
    description: Option<String>,
    #[serde(rename = "external_references")]
    external_references: Option<Vec<ExternalReference>>,
    #[serde(rename = "kill_chain_phases")]
    kill_chain_phases: Option<Vec<KillChainPhase>>,
    aliases: Option<Vec<String>>,
    #[serde(rename = "x_mitre_platforms")]
    platforms: Option<Vec<String>>,
    #[serde(rename = "x_mitre_tactics")]
    tactics: Option<Vec<String>>,
    #[serde(rename = "x_mitre_shortname")]
    shortname: Option<String>,
    #[serde(rename = "x_mitre_version")]
    version: Option<String>,
    #[serde(rename = "x_mitre_deprecated")]
    deprecated: Option<bool>,
    #[serde(rename = "x_mitre_detection")]
    detection: Option<String>,
    #[serde(rename = "x_mitre_data_sources")]
    data_sources: Option<Vec<String>>,
    #[serde(rename = "x_mitre_effective_permissions")]
    effective_permissions: Option<Vec<String>>,
    #[serde(rename = "x_mitre_permissions_required")]
    permissions_required: Option<Vec<String>>,
    #[serde(rename = "x_mitre_system_requirements")]
    system_requirements: Option<Vec<String>>,
    #[serde(rename = "x_mitre_defense_bypassed")]
    defense_bypassed: Option<Vec<String>>,
    #[serde(rename = "x_mitre_remote_support")]
    remote_support: Option<bool>,
    #[serde(rename = "x_mitre_impact_type")]
    impact_type: Option<Vec<String>>,
    #[serde(rename = "source_ref")]
    source_ref: Option<String>,
    #[serde(rename = "target_ref")]
    target_ref: Option<String>,
    #[serde(rename = "relationship_type")]
    relationship_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExternalReference {
    source_name: String,
    external_id: Option<String>,
    url: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct KillChainPhase {
    kill_chain_name: String,
    phase_name: String,
}

fn get_matrix_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not find home directory");
    home.join(".mitre").join("matrix.json")
}

fn load_attack_data() -> Result<AttackData, Box<dyn std::error::Error>> {
    let path = get_matrix_path();
    if !path.exists() {
        eprintln!("{}", "Error: MITRE ATT&CK matrix file not found at ~/.mitre/matrix.json".red());
        eprintln!("{}", "Please run the installation script first.".yellow());
        std::process::exit(1);
    }

    let content = fs::read_to_string(path)?;
    let data: AttackData = serde_json::from_str(&content)?;
    Ok(data)
}

fn get_mitre_id(obj: &AttackObject) -> Option<String> {
    if let Some(refs) = &obj.external_references {
        for ref_obj in refs {
            if ref_obj.source_name == "mitre-attack" {
                return ref_obj.external_id.clone();
            }
        }
    }
    None
}

fn get_related_techniques<'a>(group_id: &str, data: &'a AttackData) -> Vec<&'a AttackObject> {
    let mut related_technique_ids = Vec::new();
    
    // Find all relationships where this group is the source and targets attack-patterns
    for obj in &data.objects {
        if obj.obj_type == "relationship" {
            if let (Some(source_ref), Some(target_ref), Some(relationship_type)) = 
                (&obj.source_ref, &obj.target_ref, &obj.relationship_type) {
                if source_ref == group_id && relationship_type == "uses" {
                    related_technique_ids.push(target_ref.as_str());
                }
            }
        }
    }
    
    // Get the actual technique objects
    let mut techniques = Vec::new();
    for obj in &data.objects {
        if obj.obj_type == "attack-pattern" && related_technique_ids.contains(&obj.id.as_str()) {
            techniques.push(obj);
        }
    }
    
    techniques
}

fn get_related_groups<'a>(technique_id: &str, data: &'a AttackData) -> Vec<&'a AttackObject> {
    let mut related_group_ids = Vec::new();
    
    // Find all relationships where groups use this technique
    for obj in &data.objects {
        if obj.obj_type == "relationship" {
            if let (Some(source_ref), Some(target_ref), Some(relationship_type)) = 
                (&obj.source_ref, &obj.target_ref, &obj.relationship_type) {
                if target_ref == technique_id && relationship_type == "uses" {
                    related_group_ids.push(source_ref.as_str());
                }
            }
        }
    }
    
    // Get the actual group objects
    let mut groups = Vec::new();
    for obj in &data.objects {
        if obj.obj_type == "intrusion-set" && related_group_ids.contains(&obj.id.as_str()) {
            groups.push(obj);
        }
    }
    
    groups
}

fn print_separator() {
    println!("{}", "─".repeat(80).bright_black());
}

fn print_technique_info(obj: &AttackObject, data: &AttackData) {
    println!("{}", format!("Name: {}", obj.name.as_ref().unwrap_or(&"Unknown".to_string())).bright_cyan().bold());
    
    if let Some(mitre_id) = get_mitre_id(obj) {
        println!("{}", format!("MITRE ID: {}", mitre_id).bright_green());
    }
    
    println!("{}", format!("Type: {}", obj.obj_type).bright_yellow());
    
    if let Some(desc) = &obj.description {
        println!("\n{}", "Description:".bright_white().bold());
        println!("{}", desc);
    }
    
    if let Some(tactics) = &obj.kill_chain_phases {
        println!("\n{}", "Tactics:".bright_white().bold());
        for tactic in tactics {
            if tactic.kill_chain_name == "mitre-attack" {
                println!("  • {}", tactic.phase_name.bright_magenta());
            }
        }
    }
    
    if let Some(platforms) = &obj.platforms {
        println!("\n{}", "Platforms:".bright_white().bold());
        for platform in platforms {
            println!("  • {}", platform.bright_blue());
        }
    }
    
    if let Some(perms) = &obj.permissions_required {
        println!("\n{}", "Permissions Required:".bright_white().bold());
        for perm in perms {
            println!("  • {}", perm.bright_red());
        }
    }
    
    if let Some(detection) = &obj.detection {
        println!("\n{}", "Detection:".bright_white().bold());
        println!("{}", detection);
    }
    
    if let Some(data_sources) = &obj.data_sources {
        println!("\n{}", "Data Sources:".bright_white().bold());
        for source in data_sources {
            println!("  • {}", source.bright_cyan());
        }
    }
    
    // Show which groups use this technique
    let related_groups = get_related_groups(&obj.id, data);
    if !related_groups.is_empty() {
        println!("\n{}", "Used by Groups:".bright_white().bold());
        let mut sorted_groups = related_groups;
        sorted_groups.sort_by(|a, b| {
            a.name.as_ref().unwrap_or(&"".to_string())
                .cmp(b.name.as_ref().unwrap_or(&"".to_string()))
        });
        
        for group in sorted_groups {
            if let Some(group_name) = &group.name {
                let mitre_id = get_mitre_id(group).unwrap_or_else(|| "N/A".to_string());
                println!("  {} {}", format!("[{}]", mitre_id).bright_green(), group_name.bright_white());
            }
        }
    }
    
    if let Some(refs) = &obj.external_references {
        println!("\n{}", "References:".bright_white().bold());
        for ref_obj in refs {
            if let Some(url) = &ref_obj.url {
                println!("  • {} - {}", ref_obj.source_name.bright_green(), url.bright_blue().underline());
            }
        }
    }
}

fn print_group_info(obj: &AttackObject, data: &AttackData) {
    println!("{}", format!("Name: {}", obj.name.as_ref().unwrap_or(&"Unknown".to_string())).bright_cyan().bold());
    
    if let Some(mitre_id) = get_mitre_id(obj) {
        println!("{}", format!("MITRE ID: {}", mitre_id).bright_green());
    }
    
    println!("{}", format!("Type: {}", obj.obj_type).bright_yellow());
    
    if let Some(aliases) = &obj.aliases {
        println!("\n{}", "Aliases:".bright_white().bold());
        for alias in aliases {
            println!("  • {}", alias.bright_magenta());
        }
    }
    
    if let Some(desc) = &obj.description {
        println!("\n{}", "Description:".bright_white().bold());
        println!("{}", desc);
    }
    
    // Find related techniques through relationships
    let related_techniques = get_related_techniques(&obj.id, data);
    if !related_techniques.is_empty() {
        println!("\n{}", "Used Techniques:".bright_white().bold());
        
        // Group techniques by tactic
        let mut tactics_map: HashMap<String, Vec<&AttackObject>> = HashMap::new();
        
        for technique in &related_techniques {
            if let Some(phases) = &technique.kill_chain_phases {
                for phase in phases {
                    if phase.kill_chain_name == "mitre-attack" {
                        let tactic_name = phase.phase_name.replace("-", " ");
                        let tactic_name = tactic_name.split_whitespace()
                            .map(|s| s.chars().next().unwrap().to_uppercase().collect::<String>() + &s[1..])
                            .collect::<Vec<_>>()
                            .join(" ");
                        
                        tactics_map.entry(tactic_name)
                            .or_insert_with(Vec::new)
                            .push(technique);
                    }
                }
            }
        }
        
        // Sort tactics alphabetically
        let mut sorted_tactics: Vec<_> = tactics_map.iter().collect();
        sorted_tactics.sort_by(|a, b| a.0.cmp(b.0));
        
        for (tactic, techniques) in sorted_tactics {
            println!("\n  {}", format!("{}:", tactic).bright_magenta().bold());
            let mut sorted_techniques = techniques.clone();
            sorted_techniques.sort_by(|a, b| {
                a.name.as_ref().unwrap_or(&"".to_string())
                    .cmp(b.name.as_ref().unwrap_or(&"".to_string()))
            });
            
            for technique in sorted_techniques {
                if let Some(tech_name) = &technique.name {
                    let mitre_id = get_mitre_id(technique).unwrap_or_else(|| "N/A".to_string());
                    println!("    {} {}", format!("[{}]", mitre_id).bright_green(), tech_name.bright_white());
                }
            }
        }
        
        println!("\n{}", format!("Total Techniques: {}", related_techniques.len()).bright_cyan());
    }
    
    if let Some(refs) = &obj.external_references {
        println!("\n{}", "References:".bright_white().bold());
        for ref_obj in refs {
            if let Some(url) = &ref_obj.url {
                println!("  • {} - {}", ref_obj.source_name.bright_green(), url.bright_blue().underline());
            }
        }
    }
}

fn print_tactic_info(obj: &AttackObject) {
    println!("{}", format!("Name: {}", obj.name.as_ref().unwrap_or(&"Unknown".to_string())).bright_cyan().bold());
    
    if let Some(shortname) = &obj.shortname {
        println!("{}", format!("Short Name: {}", shortname).bright_green());
    }
    
    println!("{}", format!("Type: {}", obj.obj_type).bright_yellow());
    
    if let Some(desc) = &obj.description {
        println!("\n{}", "Description:".bright_white().bold());
        println!("{}", desc);
    }
    
    if let Some(refs) = &obj.external_references {
        println!("\n{}", "References:".bright_white().bold());
        for ref_obj in refs {
            if let Some(url) = &ref_obj.url {
                println!("  • {} - {}", ref_obj.source_name.bright_green(), url.bright_blue().underline());
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let data = load_attack_data()?;

    match &cli.command {
        Commands::AptList => {
            println!("{}", "APT Groups (Advanced Persistent Threat Groups):".bright_cyan().bold());
            print_separator();
            
            let mut groups: Vec<&AttackObject> = data.objects
                .iter()
                .filter(|obj| obj.obj_type == "intrusion-set")
                .collect();
            
            groups.sort_by(|a, b| {
                a.name.as_ref().unwrap_or(&"".to_string())
                    .cmp(b.name.as_ref().unwrap_or(&"".to_string()))
            });
            
            for group in groups {
                if let Some(name) = &group.name {
                    let mitre_id = get_mitre_id(group).unwrap_or_else(|| "N/A".to_string());
                    println!("{} {}", format!("[{}]", mitre_id).bright_green(), name.bright_white());
                    
                    if let Some(aliases) = &group.aliases {
                        let alias_str = aliases.join(", ");
                        println!("  Aliases: {}", alias_str.bright_black());
                    }
                    println!();
                }
            }
        },
        
        Commands::Apt { name } => {
            let name_lower = name.to_lowercase();
            let mut found_groups = Vec::new();
            
            for obj in &data.objects {
                if obj.obj_type == "intrusion-set" {
                    let mut matched = false;
                    
                    // Check name
                    if let Some(obj_name) = &obj.name {
                        if obj_name.to_lowercase().contains(&name_lower) {
                            matched = true;
                        }
                    }
                    
                    // Also check aliases
                    if !matched {
                        if let Some(aliases) = &obj.aliases {
                            for alias in aliases {
                                if alias.to_lowercase().contains(&name_lower) {
                                    matched = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if matched {
                        found_groups.push(obj);
                    }
                }
            }
            
            if found_groups.is_empty() {
                println!("{}", format!("No APT group found matching '{}'", name).red());
            } else {
                for (i, obj) in found_groups.iter().enumerate() {
                    if i > 0 {
                        print_separator();
                    }
                    print_group_info(obj, &data);
                }
            }
        },
        
        Commands::TechniqueId { id } => {
            let id_upper = id.to_uppercase();
            let mut found = false;
            
            for obj in &data.objects {
                if obj.obj_type == "attack-pattern" {
                    if let Some(mitre_id) = get_mitre_id(obj) {
                        if mitre_id == id_upper {
                            print_technique_info(obj, &data);
                            found = true;
                            break;
                        }
                    }
                }
            }
            
            if !found {
                println!("{}", format!("No technique found with ID '{}'", id).red());
            }
        },
        
        Commands::TechniqueName { name } => {
            let name_lower = name.to_lowercase();
            let mut found = false;
            
            for obj in &data.objects {
                if obj.obj_type == "attack-pattern" {
                    if let Some(obj_name) = &obj.name {
                        if obj_name.to_lowercase().contains(&name_lower) {
                            if found {
                                print_separator();
                            }
                            print_technique_info(obj, &data);
                            found = true;
                        }
                    }
                }
            }
            
            if !found {
                println!("{}", format!("No technique found matching '{}'", name).red());
            }
        },
        
        Commands::Tactic { name } => {
            let name_lower = name.to_lowercase().replace("-", "_").replace(" ", "_");
            let mut found = false;
            
            // First look for x-mitre-tactic objects
            for obj in &data.objects {
                if obj.obj_type == "x-mitre-tactic" {
                    if let Some(obj_name) = &obj.name {
                        if obj_name.to_lowercase().replace("-", "_").replace(" ", "_").contains(&name_lower) {
                            if found {
                                print_separator();
                            }
                            print_tactic_info(obj);
                            found = true;
                        }
                    }
                    
                    if let Some(shortname) = &obj.shortname {
                        if shortname.to_lowercase().replace("-", "_").contains(&name_lower) {
                            if found {
                                print_separator();
                            }
                            print_tactic_info(obj);
                            found = true;
                        }
                    }
                }
            }
            
            // If we found a tactic, also show related techniques
            if found {
                println!("\n{}", "Related Techniques:".bright_white().bold());
                print_separator();
                
                let mut techniques: Vec<&AttackObject> = data.objects
                    .iter()
                    .filter(|obj| {
                        if obj.obj_type == "attack-pattern" {
                            if let Some(phases) = &obj.kill_chain_phases {
                                return phases.iter().any(|phase| {
                                    phase.kill_chain_name == "mitre-attack" && 
                                    phase.phase_name.to_lowercase().replace("-", "_").contains(&name_lower)
                                });
                            }
                        }
                        false
                    })
                    .collect();
                
                techniques.sort_by(|a, b| {
                    a.name.as_ref().unwrap_or(&"".to_string())
                        .cmp(b.name.as_ref().unwrap_or(&"".to_string()))
                });
                
                for technique in techniques {
                    if let Some(tech_name) = &technique.name {
                        let mitre_id = get_mitre_id(technique).unwrap_or_else(|| "N/A".to_string());
                        println!("{} {}", format!("[{}]", mitre_id).bright_green(), tech_name.bright_white());
                    }
                }
            }
            
            if !found {
                println!("{}", format!("No tactic found matching '{}'", name).red());
                println!("\n{}", "Available tactics:".bright_white().bold());
                
                let mut tactics: Vec<&AttackObject> = data.objects
                    .iter()
                    .filter(|obj| obj.obj_type == "x-mitre-tactic")
                    .collect();
                
                tactics.sort_by(|a, b| {
                    a.name.as_ref().unwrap_or(&"".to_string())
                        .cmp(b.name.as_ref().unwrap_or(&"".to_string()))
                });
                
                for tactic in tactics {
                    if let Some(tactic_name) = &tactic.name {
                        let shortname = tactic.shortname.as_ref()
                            .map(|s| format!(" ({})", s))
                            .unwrap_or_default();
                        println!("  • {}{}", tactic_name.bright_cyan(), shortname.bright_black());
                    }
                }
            }
        },
    }
    
    Ok(())
}