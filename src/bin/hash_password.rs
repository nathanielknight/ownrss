use rpassword::prompt_password;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Scrypt,
};

fn main() {
    let password = prompt_password("Password: ").unwrap();
    let password2 = prompt_password("Confirm: ").unwrap();
    if password != password2 {
        println!("Passwords don't match")
    } else {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Scrypt
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        println!("{}", password_hash);
    }
}
