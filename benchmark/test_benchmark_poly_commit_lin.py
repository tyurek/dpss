from pytest import mark
from dpss.betterpairing import G1, ZR
from dpss.polynomial import polynomials_over
from dpss.poly_commit_lin import PolyCommitLin


@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_commit(benchmark, t):
    g = G1.rand()
    h = G1.rand()
    pc = PolyCommitLin([g, h])
    phi = polynomials_over(ZR).random(t)
    benchmark(pc.commit, phi)


@mark.parametrize("t", [3, 10, 20, 33])
def test_benchmark_create_witness(benchmark, t):
    g = G1.rand()
    h = G1.rand()
    pc = PolyCommitLin([g, h])
    phi_hat = polynomials_over(ZR).random(t)
    i = ZR.random()
    benchmark(pc.create_witness, phi_hat, i)
