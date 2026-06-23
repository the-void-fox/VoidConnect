{
  description = "VoidConnect — децентрализованный P2P-мессенджер для локальной сети (Rust + egui)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Rust-тулчейн с произвольными таргетами (для кросс-сборки под Windows).
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # Библиотеки, которые egui/eframe (X11/Wayland/OpenGL) и winit грузят в
      # РАНТАЙМЕ через dlopen — их нужно положить в LD_LIBRARY_PATH.
      runtimeLibs = pkgs: with pkgs; [
        libGL
        libGLU
        xorg.libX11
        xorg.libXcursor
        xorg.libXrandr
        xorg.libXi
        xorg.libxcb
        wayland
        libxkbcommon
      ];
    in
    {
      # ── Сборка: nix build .#void-ui (GUI) / .#void-app (CLI) ────────────────
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          rlibs = runtimeLibs pkgs;

          mkPkg = { pname, crate, bin, gui ? true }:
            pkgs.rustPlatform.buildRustPackage {
              inherit pname;
              version = "0.1.0";
              src = ./.;

              # Используем закоммиченный Cargo.lock (все зависимости — с crates.io,
              # git-зависимостей нет → vendor-hash не нужен).
              cargoLock.lockFile = ./Cargo.lock;

              # Собираем только нужный крейт воркспейса.
              cargoBuildFlags = [ "-p" crate ];

              # void-db читает offline-кэш sqlx вместо живой БД (см. .cargo/config.toml).
              SQLX_OFFLINE = "true";

              nativeBuildInputs = [ pkgs.pkg-config ]
                ++ pkgs.lib.optional gui pkgs.makeWrapper;
              # gtk3/glib нужны rfd (нативные файловые диалоги); GL/X11/Wayland — egui.
              buildInputs = [ pkgs.gtk3 pkgs.glib ]
                ++ pkgs.lib.optionals gui rlibs;

              # Тесты гоняем в dev-окружении (`nix develop` → cargo test); для GUI-сборки
              # пропускаем (часть требует дисплея/сети).
              doCheck = false;

              # GUI-бинарь dlopen'ит GL/Wayland/X11 в рантайме — оборачиваем с путём к ним.
              postInstall = pkgs.lib.optionalString gui ''
                wrapProgram $out/bin/${bin} \
                  --prefix LD_LIBRARY_PATH : ${pkgs.lib.makeLibraryPath rlibs} \
                  --set-default WINIT_UNIX_BACKEND x11
              '';

              meta = with pkgs.lib; {
                description = "Децентрализованный P2P-мессенджер для LAN: чат, файлы, сайты .void, голосования";
                mainProgram = bin;
                platforms = platforms.linux;
              };
            };
        in
        {
          void-ui = mkPkg { pname = "void-connect"; crate = "void-ui"; bin = "void-connect"; };
          void-app = mkPkg { pname = "void-app"; crate = "void-app"; bin = "void-app"; gui = false; };
          default = self.packages.${system}.void-ui;
        });

      # ── Запуск: nix run ─────────────────────────────────────────────────────
      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.void-ui}/bin/void-connect";
        };
        void-app = {
          type = "app";
          program = "${self.packages.${system}.void-app}/bin/void-app";
        };
      });

      # ── Разработка: nix develop ─────────────────────────────────────────────
      # Зеркало shell.nix: тулчейн Rust (+ windows-gnu target) + библиотеки egui/rfd.
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rlibs = runtimeLibs pkgs;
          # Один тулчейн: host + std для Windows-кросса (make windows через zig).
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-analyzer" "rust-src" ];
            targets = [ "x86_64-pc-windows-gnu" ];
          };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [ rustToolchain ] ++ (with pkgs; [
              # Нативные диалоги (rfd) + pkg-config
              gtk3
              glib
              pkg-config
              wayland-protocols
              # Упаковка через Makefile (linux/appimage)
              patchelf
              curl
              appimage-run
              # Кросс-сборка под Windows (make windows)
              cargo-zigbuild
              zig
            ]) ++ rlibs;

            shellHook = ''
              export WINIT_UNIX_BACKEND=x11
              export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath rlibs}:$LD_LIBRARY_PATH
            '';
          };
        });

      # Удобный алиас под `nix fmt`.
      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
