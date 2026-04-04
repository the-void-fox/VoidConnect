{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust
    rustc
    cargo
    rustfmt
    clippy
    rust-analyzer

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