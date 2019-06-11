package keyproof

const almostSafePrimeProductNonceSize = 256 // Probably not that important
const almostSafePrimeProductIters = 250     // needed since error prob is 4/5
const disjointPrimeProductIters = 8         // error prob of 1/minimumFactor
const primePowerProductIters = 80           // error prob of 1/2
const squareFreeIters = 8                   // error prob of 1/minimumFactor

const minimumFactor = 1024

const rangeProofIters = 80    // Binary challenge, so error rate of 1/2
const rangeProofEpsilon = 256 // Number of bits for statistical hiding
