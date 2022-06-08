#from adkg.betterpairing import ZR, G1, G2, pair
from pypairing import G1, G2, ZR, blsmultiexp, pair
from adkg.polynomial import polynomials_over


class PolyCommitConst:
    def __init__(self, pk, field=ZR):
        assert len(pk) == 3, "invalid crs"
        (self.gs, self.ghats, self.hs) = pk
        assert len(self.gs) == len(self.hs), "invalid crs"
        self.t = len(self.gs) - 1
        self.gg = pair(self.gs[0], self.ghats[0])
        self.gh = pair(self.hs[0], self.ghats[0])
        self.field = field

    def commit(self, phi, phi_hat=None):
        c_g = blsmultiexp(self.gs, phi.coeffs)
        
        if phi_hat is None:
            phi_hat = polynomials_over(self.field).random(self.t)
            c_h = blsmultiexp(self.hs, phi_hat.coeffs)
            c = c_g * c_h
            return c, phi_hat

        c_h = blsmultiexp(self.hs, phi_hat.coeffs)
        c = c_g * c_h
        return c

    def create_witness(self, phi, phi_hat, i):
        poly = polynomials_over(self.field)
        div = poly([-1 * i, 1])
        psi = (phi - poly([phi(i)])) / div
        psi_hat = (phi_hat - poly([phi_hat(i)])) / div
        witness_g = blsmultiexp(self.gs[:-1], psi.coeffs)
        witness_h = blsmultiexp(self.hs[:-1], psi_hat.coeffs)
        witness = witness_g * witness_h
        return witness

    def double_batch_create_witness(self, phi_list, phi_hat_list, indices):
        return [ [ self.create_witness(phi_list[j], phi_hat_list[j], indices[i]) for j in range(len(phi_list))] for i in range(len(indices))]

    # If reusing the same commitment, the lhs of the comparison will be the same.
    # Take advantage of this to save pairings
    def verify_eval(self, c, i, phi_at_i, phi_hat_at_i, witness):
        lhs = pair(c, self.ghats[0])
        rhs = (
            #pair(witness, self.ghats[1] / (self.ghats[0] ** i))
            pair(witness, self.ghats[1] * (self.ghats[0].pow(-i)))
            * self.gg ** phi_at_i
            * self.gh ** phi_hat_at_i
        )
        return lhs == rhs

    def batch_verify_eval(self, commits, i, shares, auxes, witnesses):
        assert (
            len(commits) == len(shares)
            and len(commits) == len(witnesses)
            and len(commits) == len(auxes)
        ), "invalid lengths for batch_verify_eval"
        commitprod = G1.identity()
        witnessprod = G1.identity()
        sharesum = ZR(0)
        auxsum = ZR(0)
        for j in range(len(commits)):
            commitprod *= commits[j]
            witnessprod *= witnesses[j]
            sharesum += shares[j]
            auxsum += auxes[j]
        lhs = pair(commitprod, self.ghats[0])
        rhs = (
            pair(witnessprod, self.ghats[1] * self.ghats[0].pow(-i))
            * (self.gg ** sharesum)
            * (self.gh ** auxsum)
        )
        return lhs == rhs

    def preprocess_verifier(self, level=4):
        self.gg.preprocess(level)
        self.gh.preprocess(level)

    def preprocess_prover(self, level=4):
        for item in self.gs:
            item.preprocess(level)
        for item in self.hs:
            item.preprocess(level)


def gen_pc_const_crs(t, alpha=None, g=None, h=None, ghat=None):
    nonetype = type(None)
    assert type(t) is int
    assert type(alpha) in (ZR, int, nonetype)
    assert type(g) in (G1, nonetype)
    assert type(h) in (G1, nonetype)
    assert type(ghat) in (G2, nonetype)
    if alpha is None:
        alpha = ZR.random(0)
    if g is None:
        g = G1.rand([0, 0, 0, 1])
    if h is None:
        h = G1.rand([0, 0, 0, 1])
    if ghat is None:
        ghat = G2.rand([0, 0, 0, 1])
    (gs, ghats, hs) = ([], [], [])
    for i in range(t + 1):
        gs.append(g ** (alpha ** i))
    for i in range(2):
        ghats.append(ghat ** (alpha ** i))
    for i in range(t + 1):
        hs.append(h ** (alpha ** i))
    crs = [gs, ghats, hs]
    return crs
