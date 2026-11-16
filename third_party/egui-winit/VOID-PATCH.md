# egui-winit 0.27.2 с исправлением для Void Connect

Копия крейта [egui-winit](https://github.com/emilk/egui/tree/0.27.2/crates/egui-winit)
0.27.2 (MIT OR Apache-2.0, автор — Emil Ernerfeldt), подключённая через
`[patch.crates-io]` в корневом `Cargo.toml`.

Изменение одно — в `src/lib.rs`, `State::on_keyboard_input` (помечено
`VOID-PATCH`): при нелатинской раскладке (русской и т. п.) Ctrl+V, Ctrl+C,
Ctrl+X, Ctrl+A не работали в текстовых полях — логическая клавиша приходила как
«м», «с», и egui её не распознавал. Теперь в этом случае используется физическая
клавиша. Так же сделано в egui 0.28 (issue emilk/egui#3653).

При переходе на egui 0.28+ эту копию и `[patch.crates-io]` нужно удалить.
