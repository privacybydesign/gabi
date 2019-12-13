package keyproof

const almostSafePrimeProductNonceSize = 256 // Probably not that important
const almostSafePrimeProductIters = 250     // needed since error prob is 4/5 per iter
const disjointPrimeProductIters = 8         // error prob of 1/minimumFactor per iter
const primePowerProductIters = 80           // error prob of 1/2 per iter
const squareFreeIters = 8                   // error prob of 1/minimumFactor per iter

const minimumFactor = 1024

const rangeProofIters = 80    // Binary challenge, so error rate of 1/2 per iter
const rangeProofEpsilon = 256 // Number of bits for statistical hiding
