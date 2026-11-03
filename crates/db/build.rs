// `sqlx::migrate!` встраивает миграции при компиляции, но сам не следит за
// каталогом: без этого новый *.sql не попадал в сборку до `cargo clean -p void-db`
// («no such table» во время работы). Рекомендация из документации sqlx.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
