use std::{env, io::Result, process::exit};

use crate::{app::App, config::AppConfig};

mod app;
mod current_screen;
mod state;
mod input_mode;
mod config;
mod vault_entry;

// mod mock_core;

fn main() -> Result<()> {    

    let args: Vec<String> = env::args().collect();

    let app_config = match AppConfig::build(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Error creating config: {error}");
            exit(1);
        }
    };

    let mut terminal = ratatui::init();

    let app_result = App::new(app_config).run(&mut terminal);

    ratatui::restore();

    app_result
}

