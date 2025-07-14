FROM gcr.io/oss-fuzz-base/base-builder
RUN mkdir $SRC/oss-fuzz-auto
COPY build.sh $SRC/
COPY . $SRC/oss-fuzz-auto/
WORKDIR $SRC/oss-fuzz-auto