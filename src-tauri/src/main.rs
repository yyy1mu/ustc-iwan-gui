#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod iwan;
mod proxy;
mod service;

use tauri::Manager;
use tauri_plugin_deep_link::DeepLinkExt;

fn main() {
    configure_appimage_runtime();

    if std::env::args().nth(1).as_deref() == Some("--iwan-service") {
        service::run_service_process();
    }

    if std::env::args().nth(1).as_deref() == Some("--iwan-proxy") {
        proxy::run_proxy_process();
    }

    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Do not run the USTC-iWAN GUI with sudo. Start it as a normal user; root is used only for --iwan-service.");
        std::process::exit(1);
    }

    let mut builder = tauri::Builder::default()
        .manage(iwan::FlowState::default())
        .invoke_handler(tauri::generate_handler![
            iwan::start_login,
            iwan::get_last_result,
            iwan::check_requirements,
            iwan::start_proxy,
            iwan::stop_proxy,
            iwan::get_proxy_status
        ]);

    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));
    }

    builder = builder.plugin(tauri_plugin_deep_link::init());

    builder = builder.on_window_event(|_window, event| {
        if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
            iwan::stop_proxy_on_exit();
        }
    });

    builder
        .setup(|app| {
            #[cfg(any(target_os = "linux", windows))]
            {
                app.deep_link().register_all()?;
            }

            if let Ok(Some(urls)) = app.deep_link().get_current() {
                iwan::handle_deep_link_urls(
                    app.handle().clone(),
                    urls.into_iter().map(|u| u.to_string()).collect(),
                );
            }

            let app_handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                let urls = event.urls().iter().map(|url| url.to_string()).collect();
                iwan::handle_deep_link_urls(app_handle.clone(), urls);
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building USTC iWAN")
        .run(|_app, event| {
            if matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                iwan::stop_proxy_on_exit();
            }
        });
}

#[cfg(target_os = "linux")]
fn configure_appimage_runtime() {
    if std::env::var_os("APPIMAGE").is_none() {
        return;
    }

    // Avoid loading host GVFS modules with the AppImage-bundled GLib/GIO.
    // Mismatched versions can fail on newer distributions with libgvfscommon symbol errors.
    std::env::set_var("GIO_USE_VFS", "local");
    std::env::set_var("GIO_MODULE_DIR", "/nonexistent");
}

#[cfg(not(target_os = "linux"))]
fn configure_appimage_runtime() {}
