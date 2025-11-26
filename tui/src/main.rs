use std::io::Result;

use crate::app::App;

mod app;
mod current_screen;

fn main() -> Result<()> {    
    let mut terminal = ratatui::init();
    let app_result = App::default().run(&mut terminal);
    ratatui::restore();
    app_result
}