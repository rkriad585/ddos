{
  description = "ddos bounded network diagnostics CLI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.stdenv.mkDerivation {
            pname = "ddos";
            version = "0.0.0-beta-2";
            src = ./.;
            nativeBuildInputs = [ pkgs.rustc pkgs.cargo ];
            buildPhase = "cargo build --release --locked --offline";
            installPhase = "mkdir -p $out/bin; cp target/release/ddos $out/bin/ddos";
          };
        });
    };
}
