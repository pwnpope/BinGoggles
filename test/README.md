## BinGoggles - Test Binaries Compilation Info

`Dockerfile` and `docker-compose.yml` files are provided to build static binaries with `musl-gcc`.

To build the binaries:
1. Make sure that the `test` folder is your current working directory
2. `source .env`
3. `docker compose up`

The binaries can still be removed from running `make clean` on the host.