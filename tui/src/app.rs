use std::io;

use ratatui::{
    DefaultTerminal, Frame,
    buffer::Buffer,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    layout::Rect,
    style::{Color, Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};
use tui_textarea::{Input, Key, TextArea};

use crate::current_screen::CurrentScreen;

#[derive(Debug, Default)]
pub struct App {
    current_screen: CurrentScreen,
    loggin_vault: bool,
    exit: bool,
}

impl App {
    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {

        let mut password_area = TextArea::default();
        password_area.set_cursor_line_style(Style::default());
        password_area.set_mask_char('\u{002A}'); //U+0021 star (*)
        password_area.set_placeholder_text("Please enter your password");
        password_area.set_style(Style::default().fg(Color::LightGreen));
        password_area.set_block(Block::default().borders(Borders::ALL).title(" Password "));

        while !self.exit {
            terminal.draw(|frame| self.draw(frame, &password_area))?;
            self.handle_events(&mut password_area)?;
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame, password_area: &TextArea<'_>) {
        match self.current_screen {
            CurrentScreen::Password => {
                frame.render_widget(password_area, frame.area());
            }
            _ => frame.render_widget(self, frame.area()),
        }
    }

    fn handle_events(&mut self, password_area: &mut TextArea<'_>) -> io::Result<()> {
        match event::read()? {
            // it's important to check that the event is a key press event as
            // crossterm also emits key release and repeat events on Windows.
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event, password_area)
            }
            _ => {}
        };
        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent, password_area: &mut TextArea<'_>) {
        match self.current_screen {
            CurrentScreen::Home => match key_event.code {
                KeyCode::Char('q') => self.exit(),
                _ => {}
            },
            CurrentScreen::Password => match key_event.into() {
                Input { key: Key::Esc, .. } => {
                    self.current_screen = CurrentScreen::Home
                },
                Input {
                    key: Key::Enter, ..
                } => {
                    if self.loggin_vault {
                        self.loggin(password_area.lines());
                    } else {
                        self.register(password_area.lines());
                    }
                }
                input => {
                    password_area.input(input);
                }
            },
            _ => {}
        }
    }

    fn exit(&mut self) {
        self.exit = true;
    }

    fn loggin(&mut self, password_lines: &[String]) {
        self.current_screen = CurrentScreen::Vault;
    }

    fn register(&mut self, password_lines: &[String]) {
        self.current_screen = CurrentScreen::Vault;
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        let title = Line::from(" Ferris Vault 🦀 ".bold());

        match self.current_screen {
            CurrentScreen::Home => render_home(title, area, buf),
            _ => {}
        }
    }
}

fn render_home(title: Line<'_>, area: Rect, buf: &mut Buffer) {
    let instructions = Line::from(vec![
        " Log in ".into(),
        "<L>".blue().bold(),
        " Create vault ".into(),
        "<C>".blue().bold(),
        " Quit ".into(),
        "<Q> ".blue().bold(),
    ]);

    let block = Block::bordered()
        .title(title.centered())
        .title_bottom(instructions.centered())
        .border_set(border::THICK);

    let welcome_text = Text::from(vec![Line::from(
        " Welcome to Ferris Vault 🦀, choose an action. ",
    )])
    .centered();

    Paragraph::new(welcome_text)
        .centered()
        .block(block)
        .render(area, buf);
}

fn render_loggin(title: Line<'_>, area: Rect, buf: &mut Buffer) {
    let instructions = Line::from(vec![
        " Log in ".into(),
        "<ENTER>".blue().bold(),
        " Back ".into(),
        "<BACKSPACE>".blue().bold(),
        " Quit ".into(),
        "<Q> ".blue().bold(),
    ]);

    let block = Block::bordered()
        .title(title.centered())
        .title_bottom(instructions.centered())
        .border_set(border::THICK);

    let welcome_text = Text::from(vec![Line::from(
        " Welcome to Ferris Vault 🦀, choose an action. ",
    )])
    .centered();

    Paragraph::new(welcome_text)
        .centered()
        .block(block)
        .render(area, buf);
}
