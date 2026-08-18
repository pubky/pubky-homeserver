pub fn init(level: log::LevelFilter) {
    env_logger::Builder::new().filter_level(level).init();
}
