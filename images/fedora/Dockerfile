FROM registry.fedoraproject.org/f32/fedora-toolbox:32

RUN dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo

COPY extra-packages /
RUN dnf -y install $(<extra-packages)
RUN rm /extra-packages

RUN dnf clean all

