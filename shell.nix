# Rust-тулчейн берём из rust-overlay (oxalica), чтобы добавить таргет
# x86_64-pc-windows-gnu: стоковый rustc из nixpkgs не содержит std для других
# таргетов, а rustup здесь нет. cargo-zigbuild затем чинит линковку (zig as linker).
{ pkgs ? import <nixpkgs> {
    overlays = [
      (import (builtins.fetchTarball {
        url = "https://github.com/oxalica/rust-overlay/archive/master.tar.gz";
      }))
    ];
  }
}:

let
  # Один тулчейн = host (Linux) + std для Windows-кросса. Профиль default уже
  # включает rustc/cargo/clippy/rustfmt; добавляем rust-analyzer/rust-src и таргет.
  rustToolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "rust-analyzer" "rust-src" ];
    targets = [ "x86_64-pc-windows-gnu" ];
  };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust (host + windows-gnu target, см. выше)
    rustToolchain

    # Для egui/eframe с X11
    libX11
    libXcursor
    libXrandr
    libXi
    libxcb

    # Для Wayland (опционально)
    wayland
    wayland-protocols
    libxkbcommon

    # OpenGL
    libGL
    libGLU

    # Для rfd (файловые диалоги)
    gtk3
    glib
    pkg-config

    # Для упаковки (make linux/appimage): RPATH-патчинг, загрузка appimagetool,
    # запуск appimagetool на NixOS без FUSE.
    patchelf
    curl
    appimage-run

    # Кросс-компиляция под Windows (make windows): zig как линкер для windows-gnu.
    cargo-zigbuild
    zig
  ];

  # Указываем X11 бэкенд явно
  shellHook = ''
    export WINIT_UNIX_BACKEND=x11
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath [
      pkgs.libGL
      pkgs.libGLU
      pkgs.libX11
      pkgs.libXi
      pkgs.libXcursor
      pkgs.libXrandr
      pkgs.wayland
      pkgs.libxkbcommon
    ]}
  '';
}
