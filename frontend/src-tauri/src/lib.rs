pub mod backend_manager;

use backend_manager::{BackendConfig, BackendManager, BackendStatus};
use std::sync::Arc;
use tauri::State;

#[tauri::command]
fn get_backend_config(manager: State<'_, Arc<BackendManager>>) -> Result<BackendConfig, String> {
    manager.spawn_backend()
}

#[tauri::command]
fn get_backend_status(manager: State<'_, Arc<BackendManager>>) -> BackendStatus {
    manager.get_status()
}

#[tauri::command]
fn shutdown_backend(manager: State<'_, Arc<BackendManager>>) -> Result<(), String> {
    manager.shutdown_backend()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let backend_manager = Arc::new(BackendManager::new());
    let manager_clone = backend_manager.clone();

    tauri::Builder::default()
        .manage(backend_manager)
        .invoke_handler(tauri::generate_handler![
            get_backend_config,
            get_backend_status,
            shutdown_backend
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .on_window_event(move |_app_handle, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let _ = manager_clone.shutdown_backend();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
