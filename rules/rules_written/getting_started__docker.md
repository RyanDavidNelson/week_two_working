# Docker

Source: https://rules.ectf.mitre.org/2026/getting_started/docker.html

# Docker[¶](#docker "Permalink to this heading")

Docker is a container management system to allow reproducible, isolated builds
and runtime environments across platforms. See <https://docker.com> for more
documentation on Docker.

## Installation[¶](#installation "Permalink to this heading")

Docker Desktop can be installed at: <https://www.docker.com/products/docker-desktop/>. If you install
Docker Desktop, you will not need to install the Docker Engine.

If you don’t want to or can’t use Docker Desktop, the Docker engine can be installed on unix-based
systems by following the instructions for the specific OS at
<https://docs.docker.com/engine/install/>.

## About Docker[¶](#about-docker "Permalink to this heading")

From Docker, “Docker is an open platform for developing, shipping, and running applications. Docker
enables you to separate your applications from your infrastructure so you can deliver software
quickly. With Docker, you can manage your infrastructure in the same ways you manage your
applications.

“Docker provides the ability to package and run an application in a loosely isolated environment
called a container. The isolation and security lets you run many containers simultaneously on a
given host. Containers are lightweight and contain everything needed to run the application, so you
don’t need to rely on what’s installed on the host. You can share containers while you work, and be
sure that everyone you share with gets the same container that works in the same way.”
(<https://docs.docker.com/get-started/docker-overview/>)

The eCTF uses Docker to create a reproducible build environment so that any team can compile your
code in the exact same way, no matter their host platform.

## Dockerfiles[¶](#dockerfiles "Permalink to this heading")

From Docker: “A Dockerfile is a text-based document that’s used to create a container image. It
provides instructions to the image builder on the commands to run, files to copy, startup command,
and more.”
(<https://docs.docker.com/get-started/docker-concepts/building-images/writing-a-dockerfile/>)

In the eCTF, you will have to write a Dockerfile that sets up the environment for the compiled parts
of your design to be built in. The reference design provides a basic implementation that may be
sufficient, but your design will likely need to extend the provided implementation.

