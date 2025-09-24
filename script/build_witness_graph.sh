#! /bin/bash

CIRCOM_WITNESSCALC_DIR="circom-witnesscalc"
SEMAPHORE_DIR="semaphore"
WITNESS_GRAPH_DIR="witness_graph"
CURRENT_DIR=$(pwd)

# download the circom-witnesscalc repository
if [ ! -d "$CIRCOM_WITNESSCALC_DIR" ]; then
    git clone https://github.com/iden3/circom-witnesscalc.git
fi
# download the semaphore circuit repository
if [ ! -d "$SEMAPHORE_DIR" ]; then
    git clone https://github.com/semaphore-protocol/semaphore.git
fi
# Function to generate Circom circuit code for a given depth
create_circuit_code() {
    local depth=$1
    cat <<EOF
pragma circom 2.1.5;

include "semaphore.circom";

component main {public [message, scope]} = Semaphore(${depth});
EOF
}

# install the dependencies
cd $CURRENT_DIR/$SEMAPHORE_DIR
yarn install
# build all semaphore circuits
for depth in {1..32}; do
    create_circuit_code $depth > $CURRENT_DIR/$SEMAPHORE_DIR/semaphore-${depth}.circom
done
# build the witness graph
cd $CURRENT_DIR/$CIRCOM_WITNESSCALC_DIR
for depth in {1..32}; do
    cargo run --package build-circuit --bin build-circuit --release $CURRENT_DIR/$SEMAPHORE_DIR/semaphore-${depth}.circom $CURRENT_DIR/$WITNESS_GRAPH_DIR/semaphore-${depth}.bin -l $CURRENT_DIR/$SEMAPHORE_DIR/node_modules/@zk-kit/binary-merkle-root.circom/src -l $CURRENT_DIR/$SEMAPHORE_DIR/node_modules/circomlib/circuits -l $CURRENT_DIR/$SEMAPHORE_DIR/packages/circuits/src
done
# save the witness graph to the witness_graph directory
