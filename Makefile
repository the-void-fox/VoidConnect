##############################################################################
# Void Connect — Makefile
# Использование (внутри nix-shell):
#   make linux      — нативный Linux бинарник
#   make appimage   — AppImage для Linux
#   make windows    — .exe для Windows (нужен cargo-zigbuild или mingw)
#   make all        — все три
#   make clean      — удалить dist/ и tools/
##############################################################################

CARGO_BIN  := void-connect
APP_NAME   := void-connect
APP_VER    := $(shell grep '^version' ui/Cargo.toml | head -1 | cut -d'"' -f2)
DIST       := dist

# Нативный Linux-таргет (мы уже на x86_64-linux, поэтому кросс-компиляция не нужна)
TARGET_LIN := x86_64-unknown-linux-gnu
TARGET_WIN := x86_64-pc-windows-gnu

BIN_LIN    := target/$(TARGET_LIN)/release/$(CARGO_BIN)
BIN_WIN    := target/$(TARGET_WIN)/release/$(CARGO_BIN).exe

ICON       := ui/src/assets/icon.png

APPIMAGETOOL_URL := https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
APPIMAGETOOL     := tools/appimagetool.AppImage

.PHONY: all linux appimage windows clean sizes _appdir _bundle_libs

all: linux appimage windows

# ── 1. Linux native ───────────────────────────────────────────────────────────
linux: $(DIST)/$(APP_NAME)-$(APP_VER)-linux-x86_64

$(DIST)/$(APP_NAME)-$(APP_VER)-linux-x86_64: $(BIN_LIN)
	@mkdir -p $(DIST)

	cargo build --release --target $(TARGET_LIN) -p void-ui
	cp $(BIN_LIN) $@
	
	@echo "✅  Linux → $@"

$(BIN_LIN):
	# Нативная сборка: цель совпадает с хостом, zigbuild не нужен
	cargo build --release --target $(TARGET_LIN) -p void-ui
	# Убираем /nix/store пути из RPATH для переносимости на обычный Linux
	patchelf --set-rpath '$$ORIGIN/lib:/usr/lib:/usr/lib/x86_64-linux-gnu' $@


# ── 2. AppImage ───────────────────────────────────────────────────────────────
appimage: $(DIST)/$(APP_NAME)-$(APP_VER)-x86_64.AppImage

$(APPIMAGETOOL):
	@echo "→ Скачиваю appimagetool…"
	@mkdir -p tools
	@if command -v curl >/dev/null 2>&1; then \
	    curl -fL --progress-bar -o $(APPIMAGETOOL) $(APPIMAGETOOL_URL); \
	elif command -v wget >/dev/null 2>&1; then \
	    wget -q --show-progress -O $(APPIMAGETOOL) $(APPIMAGETOOL_URL); \
	else \
	    echo "❌  Нужен curl или wget (оба есть в shell.nix)"; exit 1; \
	fi
	chmod +x $(APPIMAGETOOL)

$(DIST)/$(APP_NAME)-$(APP_VER)-x86_64.AppImage: $(BIN_LIN) $(APPIMAGETOOL)
	@mkdir -p $(DIST)
	$(MAKE) _appdir
	env -u SOURCE_DATE_EPOCH ARCH=x86_64 appimage-run $(APPIMAGETOOL) AppDir \
	    $(DIST)/$(APP_NAME)-$(APP_VER)-x86_64.AppImage
	rm -rf AppDir
	@echo "✅  AppImage → $(DIST)/$(APP_NAME)-$(APP_VER)-x86_64.AppImage"

_appdir: $(BIN_LIN)
	rm -rf AppDir
	mkdir -p AppDir/usr/bin AppDir/usr/lib

	cp $(BIN_LIN) AppDir/usr/bin/$(APP_NAME)
	patchelf --set-rpath '$$ORIGIN/../lib' AppDir/usr/bin/$(APP_NAME)

	$(MAKE) _bundle_libs

	mkdir -p AppDir/usr/share/icons/hicolor/256x256/apps
	@if [ -f $(ICON) ]; then \
	    cp $(ICON) AppDir/usr/share/icons/hicolor/256x256/apps/$(APP_NAME).png; \
	    ln -sf usr/share/icons/hicolor/256x256/apps/$(APP_NAME).png \
	        AppDir/$(APP_NAME).png; \
	    echo "  + иконка: $(ICON)"; \
	else \
	    echo "  ⚠  Иконка не найдена ($(ICON)) — добавь 256×256 PNG"; \
	fi

	printf '[Desktop Entry]\nType=Application\nName=Void Connect\nExec=$(APP_NAME)\nIcon=$(APP_NAME)\nCategories=Network;Chat;\nComment=Decentralised P2P LAN messenger\n' \
	    > AppDir/$(APP_NAME).desktop

	printf '#!/bin/sh\nHERE="$$(dirname "$$(readlink -f "$$0")")"\nexport LD_LIBRARY_PATH="$$HERE/usr/lib:$$LD_LIBRARY_PATH"\nexec "$$HERE/usr/bin/$(APP_NAME)" "$$@"\n' \
	    > AppDir/AppRun
	chmod +x AppDir/AppRun

_bundle_libs:
	@echo "→ Bundling .so files…"
	@ldd AppDir/usr/bin/$(APP_NAME) \
	  | grep "=> /" \
	  | awk '{print $$3}' \
	  | grep -Ev '/(libc|libm|libdl|libpthread|librt|libresolv|ld-linux)[.-]' \
	  | while read lib; do \
	      echo "  + $$lib"; \
	      cp -L "$$lib" AppDir/usr/lib/ 2>/dev/null || true; \
	    done


# ── 3. Windows (.exe) ─────────────────────────────────────────────────────────
# Требует cargo-zigbuild + zig ИЛИ mingw-w64.
# Добавь в shell.nix: cargo-zigbuild zig  (или pkgsCross.mingwW64.stdenv.cc)
# Без тулчейна — мягко пропускаем (чтобы `make all` собрал linux+appimage).
windows:
	@if command -v cargo-zigbuild >/dev/null 2>&1 || command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then \
	    $(MAKE) $(DIST)/$(APP_NAME)-$(APP_VER)-windows-x86_64.exe; \
	else \
	    echo "⚠  Windows пропущен: нет cargo-zigbuild / mingw-w64."; \
	    echo "   Чтобы собрать .exe, добавь в shell.nix одно из:"; \
	    echo "     pkgs.cargo-zigbuild  pkgs.zig          (рекомендуется)"; \
	    echo "     pkgs.pkgsCross.mingwW64.stdenv.cc      (альтернатива)"; \
	fi

$(DIST)/$(APP_NAME)-$(APP_VER)-windows-x86_64.exe: $(BIN_WIN)
	@mkdir -p $(DIST)
	cp $(BIN_WIN) $@
	@echo "✅  Windows → $@"

$(BIN_WIN):
	@if command -v cargo-zigbuild >/dev/null 2>&1; then \
	    cargo zigbuild --release --target $(TARGET_WIN) -p void-ui; \
	else \
	    cargo build --release --target $(TARGET_WIN) -p void-ui; \
	fi


# ── Утилиты ───────────────────────────────────────────────────────────────────
clean:
	rm -rf $(DIST) AppDir tools
	@echo "🧹  Готово"

sizes:
	@echo "\n── Артефакты ──"
	@ls -lh $(DIST)/ 2>/dev/null || echo "(пусто)"
