This provider generates an OCI/Docker image and pushes it to a location of your choice. It uses [dinker](https://github.com/andrewbaxter/dinker) for building the image, which requires no privileges and is very fast, but can only add files.

# Installation with Terraform CDK

Run

```
cdktf provider add andrewbaxter/dinker
```

# Installation with Terraform

See the dropdown on the Registry page.

# Documentation

See the Registry or look at `docs/`.

# Building

Make sure git submodules are cloned and up to date with `git submodule update --init`.

Run

```
./build.sh
```

This will generate the source files and render the docs.
