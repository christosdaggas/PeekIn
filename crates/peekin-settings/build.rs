fn main() {
    // Embed the app icon so it shows up even when the icon theme lacks it
    // (e.g. running from the source tree). GtkApplication loads
    // <resource base>/icons into the icon theme automatically.
    glib_build_tools::compile_resources(
        &["../../data/icons"],
        "resources/resources.gresource.xml",
        "peekin.gresource",
    );
    println!("cargo:rerun-if-changed=../../data/icons");
}
