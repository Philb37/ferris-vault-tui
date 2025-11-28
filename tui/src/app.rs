use std::{
    fs::{OpenOptions, read_to_string},
    io::{self, Write},
};

use app_core::{
    core::vault_core::{Core, CoreService, LoggedCore, LoggedCoreService},
    password::password_restriction::PasswordRestriction,
};
use cryptography::xchacha20poly1305::{NoKeyXChaCha20Poly1305, XChaCha20Poly1305};
use password_generator::SecurePasswordGenerator;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style, Stylize},
    symbols::border,
    text::Line,
    widgets::{Block, Borders, List, ListItem},
};
use tui_textarea::{Input, Key, TextArea};
use vault_manager::{opaque_api::OpaqueApi, opaque_vault_manager::OpaqueVaultManager};

use crate::{
    config::AppConfig,
    current_screen::CurrentScreen,
    input_mode::InputMode,
    state::State,
    vault_entry::{VaultEntry, entries_to_vault_entries},
};

#[derive(Debug, Default)]
pub struct App {
    vault_core: Option<
        CoreService<OpaqueVaultManager<OpaqueApi>, SecurePasswordGenerator, NoKeyXChaCha20Poly1305>,
    >,
    vault_logged_code: Option<
        LoggedCoreService<
            OpaqueVaultManager<OpaqueApi>,
            SecurePasswordGenerator,
            XChaCha20Poly1305,
        >,
    >,
    // vault_core: Option<
    //     MockCore<OpaqueVaultManager<OpaqueApi>, SecurePasswordGenerator, NoKeyXChaCha20Poly1305>,
    // >,
    // vault_logged_code: Option<
    //     MockLoggedCore<OpaqueVaultManager<OpaqueApi>, SecurePasswordGenerator, XChaCha20Poly1305>,
    // >,
    current_screen: CurrentScreen,
    state: State,
    input_mode: InputMode,
    password_restriction: PasswordRestriction,
    app_config: AppConfig,
    exit: bool,
}

impl App {
    pub fn new(app_config: AppConfig) -> App {
        let mut list_state = ratatui::widgets::ListState::default();

        let vaults = get_vaults(&app_config.vault_store.path);

        if !vaults.is_empty() {
            list_state.select_first();
        }

        let mut state = State::default();
        state.set_vault_items(vaults);
        state.vault_items_state = list_state;

        let core_service = create_core_service(app_config.server.get_server_url());
        // let core_service = create_mocked_core_service();

        App {
            state,
            vault_core: Some(core_service),
            password_restriction: PasswordRestriction {
                length: 18,
                lower_case: true,
                upper_case: true,
                numbers: true,
                special_characters: true,
            },
            app_config,
            ..Default::default()
        }
    }

    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        let mut password_area = TextArea::default();
        password_area.set_cursor_line_style(Style::default());
        password_area.set_mask_char('\u{002A}'); //U+0021 star (*)
        password_area.set_placeholder_text("Please enter your password");
        password_area.set_style(Style::default().fg(Color::LightGreen));
        password_area.set_block(Block::default().borders(Borders::ALL).title(" Password "));

        let mut vault_name_area = TextArea::default();
        vault_name_area.set_cursor_line_style(Style::default());
        vault_name_area.set_placeholder_text("Please enter your username (vault name)");
        vault_name_area.set_style(Style::default().fg(Color::LightGreen));
        vault_name_area.set_block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Username (vault name) "),
        );

        let mut title_area = TextArea::default();
        title_area.set_placeholder_text("Enter title");

        let mut username_area = TextArea::default();
        username_area.set_placeholder_text("Enter username");

        let mut entry_areas = [title_area, username_area];
        self.state.selected_entry_textarea = 0;
        activate(&mut entry_areas[0]);
        inactivate(&mut entry_areas[1]);

        while !self.exit {
            terminal
                .draw(|frame| self.draw(frame, &password_area, &vault_name_area, &entry_areas))?;
            self.handle_events(&mut password_area, &mut vault_name_area, &mut entry_areas)?;
        }

        Ok(())
    }

    fn draw(
        &mut self,
        frame: &mut Frame,
        password_area: &TextArea<'_>,
        vault_name_area: &TextArea<'_>,
        entry_areas: &[TextArea<'_>; 2],
    ) {
        match self.current_screen {
            CurrentScreen::Home => {
                if let None = self.vault_core {
                    self.vault_core =
                        Some(create_core_service(self.app_config.server.get_server_url()));
                    // self.vault_core = Some(create_mocked_core_service());
                }

                self.render_home(frame);
            }
            CurrentScreen::VaultName => {
                self.render_vault_name(frame, vault_name_area);
            }
            CurrentScreen::Password => {
                self.render_password(frame, password_area);
            }
            CurrentScreen::Vault => {
                self.render_vault(frame);
            }
            CurrentScreen::Entry => {
                self.render_entry(frame, entry_areas);
            }
        }
    }

    fn handle_events(
        &mut self,
        password_area: &mut TextArea<'_>,
        vault_name_area: &mut TextArea<'_>,
        entry_areas: &mut [TextArea<'_>; 2],
    ) -> io::Result<()> {
        match event::read()? {
            // it's important to check that the event is a key press event as
            // crossterm also emits key release and repeat events on Windows.
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event, password_area, vault_name_area, entry_areas)
            }
            _ => {}
        };
        Ok(())
    }

    fn handle_key_event(
        &mut self,
        key_event: KeyEvent,
        password_area: &mut TextArea<'_>,
        vault_name_area: &mut TextArea<'_>,
        entry_areas: &mut [TextArea<'_>; 2],
    ) {
        match self.current_screen {
            CurrentScreen::Home => match key_event.code {
                KeyCode::Char('q') => self.exit(),
                KeyCode::Char('c') => {
                    self.update_state_screen(CurrentScreen::VaultName, InputMode::Register)
                }
                KeyCode::Enter => {
                    self.update_state_screen(CurrentScreen::Password, InputMode::Loggin)
                }
                KeyCode::Up => self.previous_vault(),
                KeyCode::Down => self.next_vault(),
                _ => {}
            },
            CurrentScreen::VaultName => match key_event.into() {
                Input { key: Key::Esc, .. } => {
                    self.update_state_screen(CurrentScreen::Home, InputMode::Neutral)
                }
                Input {
                    key: Key::Enter, ..
                } => match self.input_mode {
                    InputMode::Register => {
                        self.update_state_screen(CurrentScreen::Password, InputMode::Register);
                    }
                    _ => {}
                },
                input => {
                    vault_name_area.input(input);
                }
            },
            CurrentScreen::Password => match key_event.into() {
                Input { key: Key::Esc, .. } => {
                    self.update_state_screen(CurrentScreen::Home, InputMode::Neutral)
                }
                Input {
                    key: Key::Enter, ..
                } => match self.input_mode {
                    InputMode::Loggin => self.loggin(password_area.lines()),
                    InputMode::Register => {
                        self.register(vault_name_area.lines(), password_area.lines())
                    }
                    _ => {}
                },
                input => {
                    password_area.input(input);
                }
            },
            CurrentScreen::Vault => match key_event.code {
                KeyCode::Char('q') => self.exit(),
                KeyCode::Char('c') => match &self.vault_logged_code {
                    Some(vault_logged_core) => vault_logged_core
                        .copy_to_clipboard(
                            self.get_vault_entries()
                                .get(self.state.index_entry_item)
                                .unwrap()
                                .0
                                .password
                                .clone(),
                        )
                        .unwrap(),
                    None => {
                        panic!("Internal error, shouldn't call vault logged core at this time.")
                    }
                },
                KeyCode::Enter => match &self.vault_logged_code {
                    Some(vault_logged_core) => {
                        vault_logged_core.save_vault().unwrap();
                        self.update_state_screen(CurrentScreen::Vault, InputMode::Neutral);
                    }
                    None => {
                        panic!("Internal error, shouldn't call vault logged core at this time.")
                    }
                },
                KeyCode::Char('a') => {
                    self.update_state_screen(CurrentScreen::Entry, InputMode::CreatingEntry)
                }
                KeyCode::Up => self.previous_entry(),
                KeyCode::Down => self.next_entry(),
                _ => {}
            },
            CurrentScreen::Entry => match key_event.into() {
                Input { key: Key::Esc, .. } => {
                    self.update_state_screen(CurrentScreen::Vault, InputMode::Neutral)
                }
                Input { key: Key::Tab, .. } => {
                    inactivate(&mut entry_areas[self.state.selected_entry_textarea]);
                    self.state.selected_entry_textarea =
                        (self.state.selected_entry_textarea + 1) % 2;
                    activate(&mut entry_areas[self.state.selected_entry_textarea]);
                }
                Input {
                    key: Key::Enter, ..
                } => match self.input_mode {
                    InputMode::CreatingEntry => {
                        match &mut self.vault_logged_code {
                            Some(vault_logged_core) => vault_logged_core.add_entry(
                                get_value_from_lines(entry_areas[0].lines()),
                                get_value_from_lines(entry_areas[1].lines()),
                                String::from_utf8(
                                    vault_logged_core
                                        .generate_password(&self.password_restriction)
                                        .unwrap(),
                                )
                                .unwrap(),
                            ),
                            None => {
                                panic!(
                                    "Internal error, shouldn't call vault logged core at this time."
                                )
                            }
                        };
                        self.update_state_screen(CurrentScreen::Vault, InputMode::Neutral);
                    }
                    // InputMode::EditingEntry => {}
                    _ => {}
                },
                input => {
                    entry_areas[self.state.selected_entry_textarea].input(input);
                }
            },
        }
    }

    fn exit(&mut self) {
        self.exit = true;
    }

    fn loggin(&mut self, password_lines: &[String]) {
        let password = get_value_from_lines(password_lines);

        let username = match self
            .state
            .get_vault_items()
            .get(self.state.index_vault_item)
        {
            Some(value) => value,
            None => {
                return;
            }
        };

        let core = self.vault_core.take();

        let logged_core = match core {
            Some(core) => core.logging_in(username, &password).unwrap(),
            _ => panic!("Internal error occured, couldn't find Core"),
        };

        self.vault_logged_code = Some(logged_core);

        self.update_state_screen(CurrentScreen::Vault, InputMode::Neutral);
    }

    fn register(&mut self, username_lines: &[String], password_lines: &[String]) {
        let password = get_value_from_lines(password_lines);

        let username = get_value_from_lines(username_lines);

        let core = self.vault_core.take();

        let logged_core = match core {
            Some(core) => core.create_account(&username, &password).unwrap(),
            _ => panic!("Internal error occured, couldn't find Core"),
        };

        self.vault_logged_code = Some(logged_core);

        self.state.add_vault_item(&username);
        add_vault_name_to_vault_store(&self.app_config.vault_store.path, username);

        self.update_state_screen(CurrentScreen::Vault, InputMode::Neutral);
    }

    fn previous_vault(&mut self) {
        let entries = self.state.get_vault_items();

        if entries.is_empty() {
            return;
        }

        if self.state.index_vault_item > 0 {
            self.state.index_vault_item -= 1;
        } else {
            self.state.index_vault_item = entries.len() - 1;
        }

        self.state
            .vault_items_state
            .select(Some(self.state.index_vault_item));
    }

    fn next_vault(&mut self) {
        let entries = self.state.get_vault_items();

        if entries.is_empty() {
            return;
        }

        if self.state.index_vault_item < entries.len() - 1 {
            self.state.index_vault_item += 1;
        } else {
            self.state.index_vault_item = 0;
        }

        self.state
            .vault_items_state
            .select(Some(self.state.index_vault_item));
    }

    fn previous_entry(&mut self) {
        let entries = self.get_vault_entries();

        if entries.is_empty() {
            return;
        }

        if self.state.index_entry_item > 0 {
            self.state.index_entry_item -= 1;
        } else {
            self.state.index_entry_item = entries.len() - 1;
        }

        self.state
            .vault_entries_state
            .select(Some(self.state.index_entry_item));
    }

    fn next_entry(&mut self) {
        let entries = self.get_vault_entries();

        if entries.is_empty() {
            return;
        }

        if self.state.index_entry_item < entries.len() - 1 {
            self.state.index_entry_item += 1;
        } else {
            self.state.index_entry_item = 0;
        }

        self.state
            .vault_entries_state
            .select(Some(self.state.index_entry_item));
    }

    fn render_home(&mut self, frame: &mut Frame) {
        let instructions = Line::from(vec![
            " Log in ".into(),
            "<ENTER>".blue().bold(),
            " Create vault ".into(),
            "<C>".blue().bold(),
            " Quit ".into(),
            "<Q> ".blue().bold(),
        ]);

        let block = create_main_block(instructions);

        let items: Vec<ListItem> = self
            .state
            .get_vault_items()
            .iter()
            .map(|vault_name| {
                ListItem::new(vault_name.clone())
                    .style(Style::default())
                    .fg(Color::White)
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        frame.render_stateful_widget(list, frame.area(), &mut self.state.vault_items_state);
    }

    fn render_password(&mut self, frame: &mut Frame, password_area: &TextArea<'_>) {
        frame.render_widget(password_area, frame.area());
    }

    fn render_vault_name(&mut self, frame: &mut Frame, vault_name_area: &TextArea<'_>) {
        frame.render_widget(vault_name_area, frame.area());
    }

    fn render_vault(&mut self, frame: &mut Frame) {
        let instructions = Line::from(vec![
            " Copy Password ".into(),
            "<C>".blue().bold(),
            " Add entry ".into(),
            "<A>".blue().bold(),
            " Quit ".into(),
            "<Q> ".blue().bold(),
        ]);

        let block = create_main_block(instructions);

        let items: Vec<ListItem> = self
            .get_vault_entries()
            .iter()
            .map(|entry| {
                ListItem::from(entry)
                    .style(Style::default())
                    .fg(Color::White)
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        frame.render_stateful_widget(list, frame.area(), &mut self.state.vault_entries_state);
    }

    fn render_entry(&mut self, frame: &mut Frame, entries_area: &[TextArea<'_>; 2]) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref());

        let chunks = layout.split(frame.area());

        for (entryarea, chunk) in entries_area.iter().zip(chunks.iter()) {
            frame.render_widget(entryarea, *chunk);
        }
    }

    fn update_state_screen(&mut self, next_screen: CurrentScreen, next_input: InputMode) {
        self.current_screen = next_screen;
        self.input_mode = next_input;
    }

    pub fn get_vault_entries(&self) -> Vec<VaultEntry> {
        match &self.vault_logged_code {
            Some(vault_logged_core) => entries_to_vault_entries(vault_logged_core.get_entries()),
            None => panic!("Error, shouldn't call this method at this time."),
        }
    }
}

fn inactivate(textarea: &mut TextArea<'_>) {
    textarea.set_cursor_line_style(Style::default());
    textarea.set_cursor_style(Style::default());
    textarea.set_block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::DarkGray))
            .title(" Inactive (TAB to switch) "),
    );
}

fn activate(textarea: &mut TextArea<'_>) {
    textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::UNDERLINED));
    textarea.set_cursor_style(Style::default().add_modifier(Modifier::REVERSED));
    textarea.set_block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default())
            .title(" Active "),
    );
}

fn create_main_block(instructions: Line<'_>) -> Block<'_> {
    let title = Line::from(" Ferris Vault 🦀 ".bold());

    Block::bordered()
        .title(title.centered())
        .title_bottom(instructions.centered())
        .border_set(border::THICK)
}

fn get_value_from_lines(lines: &[String]) -> String {
    match lines.first() {
        Some(line) if line.len() > 0 => line.to_string(),
        _ => String::new(),
    }
}

fn create_core_service(
    server_url: String,
) -> CoreService<OpaqueVaultManager<OpaqueApi>, SecurePasswordGenerator, NoKeyXChaCha20Poly1305> {
    let api = OpaqueApi::new(server_url);
    let vault_manager = OpaqueVaultManager::new(api);
    CoreService::new(vault_manager)
}

fn add_vault_name_to_vault_store(vault_store_path: &str, username: String) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(vault_store_path)
        .unwrap();

    let line = format!("{}\n", username);

    file.write_all(line.as_bytes()).unwrap();
}

fn get_vaults(path: &str) -> Vec<String> {
    let vaults: Vec<String> = read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();

    vaults
}

// fn create_mocked_core_service()
// -> MockCore<OpaqueVaultManager<OpaqueApi>, SecurePasswordGenerator, NoKeyXChaCha20Poly1305> {
//     MockCore {
//         _phantom_nkc: PhantomData,
//         _phantom_pg: PhantomData,
//         _phantom_vm: PhantomData,
//     }
// }
