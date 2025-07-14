FROM gcr.io/oss-fuzz-base/base-builder
RUN mkdir $SRC/ustp-fuzz
COPY build.sh $SRC/
COPY . $SRC/ustp-fuzz/
WORKDIR $SRC/ustp-fuzz