//! The multiples of the base point that signing, key derivation and
//! verification read.
//!
//! [`BASE`] is the comb for a secret scalar. The scalar is cut into
//! six blocks, and entry `j - 1` is the sum of the blocks' bases over
//! the set bits of `j`: with `d` the bits in a block, the base of
//! block `i` is `2^(i * d) B`. One pass down the blocks then costs
//! `d` doublings and `d` additions, against a doubling and an
//! addition for every bit of the scalar.
//!
//! [`ODD`] is for a public scalar, written in signed digits that are
//! odd and seven bits wide with at least six zeros between them:
//! entry `i` is `(2i + 1) B`, and a negative digit adds the negated
//! entry. Verification shares its doublings with the other scalar,
//! so what this table saves is additions, one for every eight bits.
//!
//! Each entry is affine and kept as `y + x`, `y - x` and `2dxy`, the
//! three values the mixed addition formula reads, so an addition
//! from a table skips the multiplications it would otherwise spend
//! on them. The tables are generated and laid out by hand rather
//! than by `rustfmt`; `base_table_is_multiples_of_b` and
//! `odd_table_is_odd_multiples_of_b` rebuild them from the base
//! point and compare every entry.

use super::Niels;
use crate::math::fe25519::Fe;

/// The comb table for edwards25519, whose blocks are 43 bits.
#[rustfmt::skip]
pub(super) const BASE: [Niels; 63] = [
    Niels {
        y_plus_x:
            Fe([0x493c6f58c3b85, 0x0df7181c325f7, 0x0f50b0b3e4cb7,
                0x5329385a44c32, 0x07cf9d3a33d4b]),
        y_minus_x:
            Fe([0x03905d740913e, 0x0ba2817d673a2, 0x23e2827f4e67c,
                0x133d2e0c21a34, 0x44fd2f9298f81]),
        xy2d:
            Fe([0x11205877aaa68, 0x479955893d579, 0x50d66309b67a0,
                0x2d42d0dbee5ee, 0x6f117b689f0c6]),
    },
    Niels {
        y_plus_x:
            Fe([0x403580dd94500, 0x48df77d92653f, 0x38a9fe3b349ea,
                0x0ea89850aafe1, 0x416b151ab706a]),
        y_minus_x:
            Fe([0x23bd617b28c85, 0x6e72ee77d5a61, 0x1a972ff174dde,
                0x3e2636373c60f, 0x0d61b8f78b2ab]),
        xy2d:
            Fe([0x0d7efe9c136b0, 0x1ab1c89640ad5, 0x55f82aef41f97,
                0x46957f317ed0d, 0x191a2af74277e]),
    },
    Niels {
        y_plus_x:
            Fe([0x489145973443a, 0x06f4d58542ace, 0x4dbb93fc694db,
                0x02b09afed4b87, 0x65cffd3a6e5cf]),
        y_minus_x:
            Fe([0x085c0a57beb04, 0x29225015a8d3c, 0x003a110ddb474,
                0x7c874d698de2b, 0x4e3f89475dce8]),
        xy2d:
            Fe([0x6dfaaab04ab63, 0x642b5d356738f, 0x66cfbdf00477d,
                0x1d4399c779e4a, 0x0fd71c689a2f4]),
    },
    Niels {
        y_plus_x:
            Fe([0x70fddd087a25f, 0x2ab87c69dddc1, 0x6acead671d4c5,
                0x1d933062b9747, 0x0854fc44544cd]),
        y_minus_x:
            Fe([0x6a4e3c715a0d2, 0x61f0683a9a2c2, 0x7a2672d4d88f2,
                0x5534b77a994e3, 0x3d4e8dbba668b]),
        xy2d:
            Fe([0x3a0c555edad19, 0x7de1507bccc3d, 0x6ea97e092d4cf,
                0x7469dbb821441, 0x678f82b898a47]),
    },
    Niels {
        y_plus_x:
            Fe([0x2bfc5e69eb07c, 0x11bc441b1c27f, 0x58b54094b3b47,
                0x3584ec7073898, 0x72ce0e5aa500d]),
        y_minus_x:
            Fe([0x4b3a4dc5c8e1a, 0x3500134030a2d, 0x534f38354cd1a,
                0x094a1d124fe1d, 0x357cea93a929e]),
        xy2d:
            Fe([0x40b7f686f4608, 0x68c20f755b3cf, 0x427589bf0be0d,
                0x180a79b1a005c, 0x4404ba43db48f]),
    },
    Niels {
        y_plus_x:
            Fe([0x1816a22d47765, 0x07d8b467c2a49, 0x5e2e3e8a424f4,
                0x6b8da575e3d9a, 0x0788f66e0c41e]),
        y_minus_x:
            Fe([0x1a7d6c573c477, 0x35ea3f88375e2, 0x6a232f949a229,
                0x51b1ea55aab62, 0x4976d00cb6fa6]),
        xy2d:
            Fe([0x706a087387805, 0x2718524ee7930, 0x3bcf2990d59d3,
                0x5d5ca17eb2cd3, 0x63954d5e3108d]),
    },
    Niels {
        y_plus_x:
            Fe([0x407fd3af50ec1, 0x3b7ca7d5a36ca, 0x27371270cd9be,
                0x06f198c98bb9c, 0x27190ae9192c1]),
        y_minus_x:
            Fe([0x7b5cd853ff8c5, 0x3dc916ea71280, 0x02a85304a777c,
                0x1400e845ec6c3, 0x2a2aee8230b20]),
        xy2d:
            Fe([0x4d542b86ecc75, 0x3bf306cf1765e, 0x39ced2ce13400,
                0x57ce8b12cc172, 0x1b1109c06b72a]),
    },
    Niels {
        y_plus_x:
            Fe([0x2d8c6f86307ce, 0x6286ba1850973, 0x5e9dcb08444d4,
                0x1a96a543362b2, 0x5da6427e63247]),
        y_minus_x:
            Fe([0x3355e9419469e, 0x1847bb8ea8a37, 0x1fe6588cf9b71,
                0x6b1c9d2db6b22, 0x6cce7c6ffb44b]),
        xy2d:
            Fe([0x4c688deac22ca, 0x6f775c3ff0352, 0x565603ee419bb,
                0x6544456c61c46, 0x58f29abfe79f2]),
    },
    Niels {
        y_plus_x:
            Fe([0x4c579399eb749, 0x2e8831e68c18b, 0x696e8eddd5e57,
                0x301655300c77f, 0x1d52d20ba5e90]),
        y_minus_x:
            Fe([0x28e92da42a113, 0x75c4df11690b6, 0x3b7553723685c,
                0x0a10febe3585e, 0x517944430a986]),
        xy2d:
            Fe([0x216eb202c1db1, 0x5ce8c4a559984, 0x254b18549a275,
                0x248835ec13794, 0x11a7b47f94253]),
    },
    Niels {
        y_plus_x:
            Fe([0x3f5fad16d6d6a, 0x6b9184db7a600, 0x286fac93e00e3,
                0x5bc79398d283b, 0x7b47341e3a8e2]),
        y_minus_x:
            Fe([0x445c5dc362cc3, 0x50cbacc837df7, 0x09ef84e136ba4,
                0x4771b954c1fc7, 0x53b46fc0d6977]),
        xy2d:
            Fe([0x0bb68a3a75d58, 0x2963d2065c604, 0x0dac9c78dca43,
                0x2e89e9750399f, 0x317ba74e62338]),
    },
    Niels {
        y_plus_x:
            Fe([0x580bb508fa298, 0x46da9e14b8a49, 0x42edff9645db2,
                0x57ece6212e3a0, 0x480d5d825fbff]),
        y_minus_x:
            Fe([0x69002a914e452, 0x49374f4b8e6c7, 0x1bd0ff9babbe2,
                0x77996099b919b, 0x7ec21f2cd1bfa]),
        xy2d:
            Fe([0x7008403136bfa, 0x74c365e83c003, 0x44728288690b9,
                0x3362c129a6d0d, 0x79980475a6971]),
    },
    Niels {
        y_plus_x:
            Fe([0x0994891c3c110, 0x612e2b471546a, 0x6c5a95df2f541,
                0x79e9c3c6627e0, 0x2debb3486c85f]),
        y_minus_x:
            Fe([0x3e83fa7f49b1b, 0x46a9460008582, 0x1c2868bd5c21b,
                0x7c79c61eae859, 0x12e7e7024c503]),
        xy2d:
            Fe([0x3190ad4a002fe, 0x7ead3d591f7e2, 0x6de96591991f0,
                0x5e11512add08f, 0x69b5c7c12cbc0]),
    },
    Niels {
        y_plus_x:
            Fe([0x115f0f05f249d, 0x0b17798b25a19, 0x0356812a5f578,
                0x78fff5135c3ef, 0x24a76575e64a9]),
        y_minus_x:
            Fe([0x577e696461bb7, 0x164b755349c05, 0x37cc5d7c463e8,
                0x13c7fc3e8f878, 0x5ad4a47f4ed46]),
        xy2d:
            Fe([0x3fe5961c795ad, 0x6db407c4866fd, 0x52978e63ae2bb,
                0x65336f18d0de7, 0x6f9307130c39a]),
    },
    Niels {
        y_plus_x:
            Fe([0x57ca5f209064d, 0x2ba1b46391747, 0x0a3fadea9630f,
                0x0f99d11ae1f24, 0x51b0476c21f84]),
        y_minus_x:
            Fe([0x091d2c3518b93, 0x6fa5597a657ba, 0x6556fc10e3371,
                0x69fc8e37eeec4, 0x26407d2f2dbaa]),
        xy2d:
            Fe([0x662c05639a28c, 0x0f1dc5298be19, 0x56ad940a59b41,
                0x264d966505909, 0x3597ab7337bae]),
    },
    Niels {
        y_plus_x:
            Fe([0x374fa557a72f2, 0x749113754fde8, 0x04c1d27820fec,
                0x277f24473eab7, 0x27edcb9401991]),
        y_minus_x:
            Fe([0x2133ddcca6e0a, 0x595efa1670e77, 0x077eb3755d407,
                0x54041b41a1f07, 0x7869d44285144]),
        xy2d:
            Fe([0x5d2114c6d4852, 0x2421f4a9c3d36, 0x7eb7414396df3,
                0x7541e2be9f02c, 0x2d49afba7e5bc]),
    },
    Niels {
        y_plus_x:
            Fe([0x6cba293a36247, 0x4564d1faca6b1, 0x2807226be3e61,
                0x2922097bf4cb4, 0x5786f312cd754]),
        y_minus_x:
            Fe([0x2d50c7ec20d3e, 0x5d4192e4c76b4, 0x7fdcd37192f75,
                0x55d2b74482960, 0x4929c6f72b2ff]),
        xy2d:
            Fe([0x788ffca14032c, 0x5088fe3dc666e, 0x46f32b7ce4840,
                0x3c1c58a038f91, 0x4c817b4bf2344]),
    },
    Niels {
        y_plus_x:
            Fe([0x2fd66130dda4c, 0x2f44b6eb3f090, 0x2eb2c7efcd3f8,
                0x4b1fec1c02ac8, 0x1e945d5bf818b]),
        y_minus_x:
            Fe([0x02288046cdbb9, 0x56cb1a5f06f3b, 0x79597746eaf49,
                0x09e6c517c31c9, 0x12f2d199c54bf]),
        xy2d:
            Fe([0x7f5fe3bb84c05, 0x7dff7165a25d3, 0x2d2bb80df65b7,
                0x08ecdbf4028ad, 0x3584b1568c8dd]),
    },
    Niels {
        y_plus_x:
            Fe([0x05e7d950a2246, 0x7f7345df34124, 0x36a2ff8397938,
                0x2b961db6ec51f, 0x7ba359d7dcf12]),
        y_minus_x:
            Fe([0x12f3650977376, 0x42ba6e4eac84e, 0x428b44c6cf76c,
                0x33ebf00f63b84, 0x07d0a60ac285e]),
        xy2d:
            Fe([0x6c23078fd2dfa, 0x19b4ab4da658b, 0x1e32e79cc3d1b,
                0x0cb651998e1b6, 0x4f49c091c852f]),
    },
    Niels {
        y_plus_x:
            Fe([0x163d1f9583bde, 0x2e95d0066e742, 0x451e6f0e8a83d,
                0x42d5c79278e9d, 0x14561e47a14f9]),
        y_minus_x:
            Fe([0x1a4bff9830705, 0x1b385042736cb, 0x725df364b67be,
                0x52afa6ba3469e, 0x4023d2ac6eb51]),
        xy2d:
            Fe([0x191e7d2f9815f, 0x4d5e1e08b1f79, 0x3d31af09b0ab3,
                0x19053411e4ae5, 0x037e5f25a9a2e]),
    },
    Niels {
        y_plus_x:
            Fe([0x5a5d34e576cb8, 0x2431caf5bf0e8, 0x38acb716b3f3e,
                0x455effe5324df, 0x7b02c11a56aff]),
        y_minus_x:
            Fe([0x122c1263fe8fd, 0x2b1821f415b7a, 0x51c4e9c84d228,
                0x5a65c4b7be95f, 0x2b758ad16642f]),
        xy2d:
            Fe([0x29c11a16447be, 0x662ed0a9b1a8b, 0x433d0bb866915,
                0x6c86e2780f0b5, 0x63cd54411ccb5]),
    },
    Niels {
        y_plus_x:
            Fe([0x542e334437139, 0x514ee2d1e5428, 0x7fd221a7ff48f,
                0x12482e7ba4b72, 0x6d2f77176cb3e]),
        y_minus_x:
            Fe([0x1666ac7c13f73, 0x5cf5f623ba414, 0x68a74fee146a1,
                0x5be4863dac24b, 0x1ad5a384d648a]),
        xy2d:
            Fe([0x2fc4b493c2763, 0x681f84a017e44, 0x2ad4cbc30c47e,
                0x31cb4f037bad5, 0x45bfa8b73be05]),
    },
    Niels {
        y_plus_x:
            Fe([0x443937fd17f17, 0x7bf9b58b39d6a, 0x75e6d6a37c1e0,
                0x1166d8d8376e9, 0x4b75c0f47c607]),
        y_minus_x:
            Fe([0x347956f41167f, 0x7b9a78e3e2879, 0x2cb85369d9db3,
                0x59627a0f6c21b, 0x79ef3f6fa0ae5]),
        xy2d:
            Fe([0x49758b9ae6977, 0x3f4b25969694f, 0x26644045a4e5f,
                0x0f29d5b8c05f0, 0x5bb107ba0f0c2]),
    },
    Niels {
        y_plus_x:
            Fe([0x1aaa9085a9623, 0x0ac55d397fcd4, 0x3633725ccff8a,
                0x3b2409b3d4b57, 0x0045287423968]),
        y_minus_x:
            Fe([0x6ff9ba1190035, 0x315a0171e2acb, 0x6c10063e96d56,
                0x3b4e0ad999cde, 0x25b6bc4c66b9f]),
        xy2d:
            Fe([0x3faf538e59996, 0x0a48dcd48d833, 0x4380f9102dc8d,
                0x093d50077c2ac, 0x1e58d67b1027e]),
    },
    Niels {
        y_plus_x:
            Fe([0x1f81b393bc2fc, 0x33e80fdc426d3, 0x138e334937f2e,
                0x754870242f18e, 0x02015a7e89d51]),
        y_minus_x:
            Fe([0x3a9d326a04a6f, 0x4e1e7c4cdcae5, 0x60cce2ae8db4b,
                0x05066dbc59177, 0x428e26f003e83]),
        xy2d:
            Fe([0x68186e27d2b60, 0x569c614a69d88, 0x508be6f18394b,
                0x6445bdba7f855, 0x1c3c682e498a3]),
    },
    Niels {
        y_plus_x:
            Fe([0x7d37e94f40e46, 0x736ec4bf3e6a9, 0x15729be1d0b9a,
                0x295240853caa4, 0x0e8349842861e]),
        y_minus_x:
            Fe([0x39a7b6ff976fe, 0x5351e36333f93, 0x0cfc391d6278e,
                0x246a91c2a7a26, 0x5ec56efdb5b69]),
        xy2d:
            Fe([0x006548833c95d, 0x3a489bdd09642, 0x173c43c8fe027,
                0x119c92a33abbd, 0x433f75bd36016]),
    },
    Niels {
        y_plus_x:
            Fe([0x02b0de5b5a273, 0x5b7953785da8e, 0x7f8db6f17827d,
                0x734f6e2f3d625, 0x021d8967a8a5c]),
        y_minus_x:
            Fe([0x757b7969a802b, 0x5801e75c5fa57, 0x6b3ccd525fe0e,
                0x5f2a26dd62ee1, 0x601ae3bc9d563]),
        xy2d:
            Fe([0x1eb337f03451a, 0x37faa46909b9f, 0x672f158b0a742,
                0x25b3869408bf9, 0x2eb3aea1833f7]),
    },
    Niels {
        y_plus_x:
            Fe([0x198d7740b7da6, 0x66f2e28bca690, 0x681bddb3a4636,
                0x148e76584abb0, 0x53f0162688a3e]),
        y_minus_x:
            Fe([0x04802f7d66f46, 0x5fdc7caaff584, 0x027e19dfef018,
                0x5f1153360c72e, 0x6098765d7feda]),
        xy2d:
            Fe([0x144d521884887, 0x69fba5d7e0f33, 0x1601c83a55e31,
                0x433569e9c60fb, 0x311baab082de5]),
    },
    Niels {
        y_plus_x:
            Fe([0x122acea8414f1, 0x633f06fec4e39, 0x74c2ff7cf57b6,
                0x08e10f59ffc50, 0x1d4ff6b5ee4c6]),
        y_minus_x:
            Fe([0x019b44ec0fbd5, 0x38178c06c34c0, 0x4cc32b6538599,
                0x2027901030f94, 0x6b83e09a3efb1]),
        xy2d:
            Fe([0x2c5e3bf891420, 0x4b0a5c49848a7, 0x4e36e46472f71,
                0x705a489f5bf1d, 0x556014daa69d8]),
    },
    Niels {
        y_plus_x:
            Fe([0x7886dea5a34b6, 0x6eb94cb2fb638, 0x12d43a460b50c,
                0x34b9b1791f76f, 0x2d8ae7f65b73b]),
        y_minus_x:
            Fe([0x44ddba9d9ffa6, 0x191648b0ba884, 0x373a9f28150bd,
                0x4e31d0110abb8, 0x21e231c9cadb0]),
        xy2d:
            Fe([0x1ca0131a056c2, 0x4e8caccb8a0cf, 0x11c8f5ae3d575,
                0x136c03e8e257f, 0x66b11412dd13b]),
    },
    Niels {
        y_plus_x:
            Fe([0x07ba6c63ee47e, 0x40070a48171d9, 0x2f19d99606406,
                0x37d034bab9e49, 0x195a99efa3f09]),
        y_minus_x:
            Fe([0x19ab5741096bf, 0x031cc57a951e4, 0x2dd79e28ecc39,
                0x48a80703e523c, 0x72b0011c52792]),
        xy2d:
            Fe([0x4e52a579f8912, 0x35623814f55ee, 0x7467cdc108b64,
                0x1468363dcde8f, 0x2c656b5c57731]),
    },
    Niels {
        y_plus_x:
            Fe([0x41e7f27a8ccf5, 0x17028a3147534, 0x01140010b0264,
                0x36527f7bd1dfc, 0x0bd65af299b9b]),
        y_minus_x:
            Fe([0x53b2d459e2380, 0x642bebefcc83c, 0x32ac287ee38fa,
                0x4765e6e0207fd, 0x0b6b8fa40ea7e]),
        xy2d:
            Fe([0x5130ce27dee1a, 0x37f4a3624c53c, 0x66df501ae5083,
                0x6b78d7b8b9577, 0x3f38dc919db72]),
    },
    Niels {
        y_plus_x:
            Fe([0x6d8475ab10761, 0x40dfa26e8dcaf, 0x40958c9c50d78,
                0x73d9a17c12766, 0x4b16281ea8791]),
        y_minus_x:
            Fe([0x5aa9062de37a1, 0x001a3b2dc3098, 0x2490b65087694,
                0x06d3c41431835, 0x3c5e464a690d1]),
        xy2d:
            Fe([0x101d50b813381, 0x22eddcd051a38, 0x0fd90277b983c,
                0x425065b44499c, 0x6183c565f6ff4]),
    },
    Niels {
        y_plus_x:
            Fe([0x7c9f030acfbb2, 0x6788ff8c251d8, 0x5a35640a4e760,
                0x0a164a68a2c95, 0x6e0bbf0bf11d2]),
        y_minus_x:
            Fe([0x435afd4f48537, 0x7295dd0828ba9, 0x217e051449103,
                0x5097876be1b68, 0x3047dbb6f925e]),
        xy2d:
            Fe([0x155760308fdcc, 0x5ec4b5e456b55, 0x00c149e076cd7,
                0x5e948a6027696, 0x33c020f1ab2ac]),
    },
    Niels {
        y_plus_x:
            Fe([0x168fb5338c4bf, 0x160bf2ab9cef5, 0x0cb091a33efaf,
                0x731166bedf83e, 0x333fcf7554dd8]),
        y_minus_x:
            Fe([0x5556e4e1f5049, 0x712cee9d19bca, 0x618f10edbf8ec,
                0x4b58fb3396134, 0x3c3e374fbc87f]),
        xy2d:
            Fe([0x107086b062fd2, 0x075d992980eed, 0x6a18e8db96401,
                0x39ae80c127d6e, 0x1e5ad40df778c]),
    },
    Niels {
        y_plus_x:
            Fe([0x31d4cd2c9ad5b, 0x2328b724b1f05, 0x7e9a5e6351469,
                0x41fabab40926e, 0x56d16f374753a]),
        y_minus_x:
            Fe([0x3328177fdc592, 0x0d5beba0c775e, 0x144fddd8a5f4a,
                0x6b8d40ca9e074, 0x3a0b2dc2ac709]),
        xy2d:
            Fe([0x433784cc1dc9f, 0x4f7ed62ef4bdc, 0x57464e273b659,
                0x453ce1c952632, 0x4e283a209f17c]),
    },
    Niels {
        y_plus_x:
            Fe([0x63a7e4c1ee79d, 0x49e878c4991ac, 0x4a5dedb9269ac,
                0x573a9b197821b, 0x52ec445b37bf7]),
        y_minus_x:
            Fe([0x6ff292110758b, 0x465a5e90125c2, 0x5936d0ce151ef,
                0x3e2458cdd8e62, 0x56acad82af431]),
        xy2d:
            Fe([0x149daccac94da, 0x0ca9be697687e, 0x3fdb6d05c116d,
                0x65068e8400907, 0x15b17816df2e8]),
    },
    Niels {
        y_plus_x:
            Fe([0x5bfb450b8e5a1, 0x5fc0dd5c5f7cd, 0x41d4a4d5cd78f,
                0x54b86df8b5da2, 0x73b25cb9010fe]),
        y_minus_x:
            Fe([0x06ff4312d165c, 0x6afb5f01a0516, 0x0f31940eff47f,
                0x31c7deb477714, 0x144cbe717c462]),
        xy2d:
            Fe([0x1b6b5e823da19, 0x6e837128cef95, 0x45c4a33b6ce38,
                0x310c30c15c85f, 0x1dce791713d48]),
    },
    Niels {
        y_plus_x:
            Fe([0x270815090624f, 0x5719bd24928a1, 0x155c32b321abb,
                0x78350202e65b2, 0x673f0ac592f9a]),
        y_minus_x:
            Fe([0x7f5476d7ff42f, 0x05d72d84fb826, 0x11478e09421d8,
                0x4a69261b5329e, 0x3abb0f4ef2410]),
        xy2d:
            Fe([0x1f14213da5c07, 0x7a2908089bb51, 0x126c10c1dc84a,
                0x1a10065b5eb79, 0x210da8c1a5d43]),
    },
    Niels {
        y_plus_x:
            Fe([0x6c8d277ede44c, 0x5ea38e851e372, 0x28a0f6698d97d,
                0x361e19f918890, 0x230bf6af188e0]),
        y_minus_x:
            Fe([0x3b7d54ac8b670, 0x149dc73222766, 0x1a083b9224508,
                0x5e010e814a51a, 0x28fa0cd5261b7]),
        xy2d:
            Fe([0x58b6264ea523d, 0x1edb8580e1f98, 0x63ec84cb3c508,
                0x6e28a14f6cb10, 0x4888e8ab92c41]),
    },
    Niels {
        y_plus_x:
            Fe([0x63866f5e5910d, 0x4d569650e2c2f, 0x0aeede0f063d3,
                0x33ec15127fd38, 0x33b460426a0e6]),
        y_minus_x:
            Fe([0x2568713a6c03b, 0x5c3cf4cfa89b4, 0x7d7c875dfd738,
                0x5d195f4fb960a, 0x0224c26c075be]),
        xy2d:
            Fe([0x7e56d246085bc, 0x4584db7322c17, 0x478626b66e531,
                0x1fc0df948b506, 0x50d03680ffb6a]),
    },
    Niels {
        y_plus_x:
            Fe([0x1f5b28858f556, 0x4f38325e62140, 0x5ee45b614bd7e,
                0x663a4fbef2c83, 0x65d66cf60afe6]),
        y_minus_x:
            Fe([0x39368a4cb74a6, 0x1e28195400c1e, 0x6bb2e64e6e172,
                0x5e3f803953713, 0x5627eec278c5f]),
        xy2d:
            Fe([0x6601061c89787, 0x7b5ff2eeb8a2c, 0x6d0a25efc1a12,
                0x562b0f26238f2, 0x2fdab870b87c7]),
    },
    Niels {
        y_plus_x:
            Fe([0x6edf85117c145, 0x5adc2235538ef, 0x6c260ff542fbc,
                0x529e6f8b2ced1, 0x237f0a70188a4]),
        y_minus_x:
            Fe([0x4e0313abeefdd, 0x2d0ef2badb7d7, 0x231d9678da2fb,
                0x78a09c93d0743, 0x76761acbb3678]),
        xy2d:
            Fe([0x196ca9d1c7a56, 0x67d1a84207f3f, 0x47953214ba756,
                0x13ea3fedb098d, 0x191fe22733320]),
    },
    Niels {
        y_plus_x:
            Fe([0x3bc7a625d1777, 0x70a38b6036bad, 0x533bdf4c6d90b,
                0x2e6dbd6578c1b, 0x158144c8e73d6]),
        y_minus_x:
            Fe([0x048bcaaebce27, 0x13fa0a44ab802, 0x3857dc79dde97,
                0x117f5a6420e38, 0x546bc1430967b]),
        xy2d:
            Fe([0x54d4c5085b7f0, 0x2d2c4ed8438bb, 0x468b8f2ad5ac3,
                0x4757b34f7bb2a, 0x391e19f312a38]),
    },
    Niels {
        y_plus_x:
            Fe([0x548d679543051, 0x3d1a3eb004f1d, 0x5f9793a620505,
                0x0fb8e0d015477, 0x1707b6d28a92d]),
        y_minus_x:
            Fe([0x3239434ccde00, 0x18119131a2ffd, 0x379a0ff82da08,
                0x570e40aa7f2c2, 0x0bf3cbe73b998]),
        xy2d:
            Fe([0x172ddf5963dc9, 0x6771c73983e4b, 0x417e5c5c8bc6e,
                0x003d70ef27328, 0x1d25b0d06514f]),
    },
    Niels {
        y_plus_x:
            Fe([0x6cd4ae936abec, 0x2d431e4991d5c, 0x1c56623324ca1,
                0x52e080eb18a09, 0x3512e63c061df]),
        y_minus_x:
            Fe([0x20b63d35e9049, 0x31b49b904eb03, 0x636a3a4e97341,
                0x16173e1a3f7d9, 0x3f4a63b4a2613]),
        xy2d:
            Fe([0x417a33510be75, 0x71f278992324e, 0x2a92cfce637ad,
                0x63e0dff471709, 0x061830ee383d6]),
    },
    Niels {
        y_plus_x:
            Fe([0x3d773412189fd, 0x0b0256c8dfc57, 0x1f1023ab00dff,
                0x27cdbbfaf8abe, 0x30cd50be537b2]),
        y_minus_x:
            Fe([0x618da8918589d, 0x19e678f45494a, 0x48e00998b05b6,
                0x49f5ce09e4910, 0x03264d90066ad]),
        xy2d:
            Fe([0x35057e4a02bd2, 0x4fc4f4a9d4938, 0x2785dda6e49d6,
                0x3894b262729d8, 0x2ef174a2f1c66]),
    },
    Niels {
        y_plus_x:
            Fe([0x65bc6bc646016, 0x2bb3c2131c551, 0x173b492d601fe,
                0x17edba4360992, 0x360f7a5d483d5]),
        y_minus_x:
            Fe([0x71d70102b3dc7, 0x1057e6d872e75, 0x06b6340fea2b8,
                0x15e21c6efccd7, 0x49429daf0911b]),
        xy2d:
            Fe([0x1da63b0723303, 0x54583e40ca80f, 0x6a0470560708e,
                0x336d6f44b1915, 0x2aaaedc0f39da]),
    },
    Niels {
        y_plus_x:
            Fe([0x7db9337becde3, 0x0ec57304294e4, 0x41f682fd589ce,
                0x1140e01aa44a0, 0x1a7f49402f536]),
        y_minus_x:
            Fe([0x32751bbbaaad7, 0x40a5286147ef7, 0x059d4564084dc,
                0x61f436b9ff5aa, 0x64fc0d43183bf]),
        xy2d:
            Fe([0x2acd0b30cf091, 0x272d561e98c8d, 0x50ac800209cc4,
                0x54b1caca68060, 0x64bffa14edeb1]),
    },
    Niels {
        y_plus_x:
            Fe([0x51bf56f17952b, 0x0a99e56a86e9f, 0x22049278d20e7,
                0x1453f2bfcdffa, 0x2cd2074a62434]),
        y_minus_x:
            Fe([0x5b68182f82907, 0x0d40aa8db526e, 0x182b84881f007,
                0x0f3c953c531a1, 0x1dc649f024a70]),
        xy2d:
            Fe([0x57bbf75fd95a9, 0x678df80eb9941, 0x57eb665520b2d,
                0x6f01e313afb2a, 0x3418f812508fa]),
    },
    Niels {
        y_plus_x:
            Fe([0x685489672b782, 0x52d52e5bf51c5, 0x254a72cb3b0b9,
                0x5f6e3e56ec569, 0x7743b7446ab30]),
        y_minus_x:
            Fe([0x7995eec50dc4c, 0x1f2c4c7918e2a, 0x5cfec1a818e23,
                0x252de49a91ae7, 0x21383d1207b69]),
        xy2d:
            Fe([0x325f03400807e, 0x18472c088beb7, 0x26b451dbf718a,
                0x6c4d20641137c, 0x2716ae275a2ef]),
    },
    Niels {
        y_plus_x:
            Fe([0x1adbdf71970ae, 0x719ff2af1cada, 0x5752ec8facbc2,
                0x4c72988815f16, 0x6c7ea0961d939]),
        y_minus_x:
            Fe([0x46f5b6ba86325, 0x27c24254e2746, 0x48678a39239dc,
                0x3adf158c67d35, 0x30ff856a27d50]),
        xy2d:
            Fe([0x536ed8fb1e855, 0x5bb6bf20da5c9, 0x4dfc88874a9f8,
                0x7db1c75bb2caf, 0x30496d554d689]),
    },
    Niels {
        y_plus_x:
            Fe([0x064c333903bcf, 0x6d280d473f771, 0x1d9997c1d8ea3,
                0x5760c02852f80, 0x42c77fa2557ea]),
        y_minus_x:
            Fe([0x72008040f9ec8, 0x5fefaf92d1840, 0x4c3b01afdc929,
                0x4173ec76ba00e, 0x4c69dcca77c18]),
        xy2d:
            Fe([0x6c400f8a452f4, 0x3ebaba084639b, 0x7f84a986de654,
                0x0d6392054d0bf, 0x2311aff411913]),
    },
    Niels {
        y_plus_x:
            Fe([0x7bd111e4dd086, 0x56e7c9a58d61d, 0x44ef411c6921b,
                0x6d7d1df35f8f8, 0x748f93488e529]),
        y_minus_x:
            Fe([0x28d45d1e95dec, 0x47269e0bf9806, 0x7c9823b289763,
                0x2688839237961, 0x7a2cdeb6eb149]),
        xy2d:
            Fe([0x686fce4d97bc8, 0x51c736297494f, 0x5a44961a80f09,
                0x1c8949e0674b2, 0x5d6a02fc9840a]),
    },
    Niels {
        y_plus_x:
            Fe([0x4a64eff5f3500, 0x04be4d9fb38e8, 0x378f587f52909,
                0x7e8e852edfa5a, 0x1bc88b69f940a]),
        y_minus_x:
            Fe([0x2d5a8248a16c0, 0x2f54b1ae3b9e2, 0x588e1cd4ae6b7,
                0x43886a4704e01, 0x085fb909d73a0]),
        xy2d:
            Fe([0x2631a4cda2a2d, 0x5135f42f7a3d8, 0x2676da251943e,
                0x32eae55b215fe, 0x4a8a4c1e04c35]),
    },
    Niels {
        y_plus_x:
            Fe([0x14b0035258eb1, 0x5e7372d3f453d, 0x47ef394639ac4,
                0x1380f5b5b1f08, 0x2a9080ecc95ac]),
        y_minus_x:
            Fe([0x5609e2f5ec332, 0x6f4e76eef7e48, 0x1300e6e82c2b2,
                0x564408247adb5, 0x0663e2bb572ef]),
        xy2d:
            Fe([0x3f0cb59db1995, 0x4f8520fd8bdea, 0x2e7ddabd5c6a4,
                0x657d19497de4a, 0x12bda65bdc492]),
    },
    Niels {
        y_plus_x:
            Fe([0x7e250e277165d, 0x140afe87d4edc, 0x3a63432eefd3b,
                0x530cfa9755cf6, 0x02fcd77d58a7c]),
        y_minus_x:
            Fe([0x3acf0bf134d03, 0x63b6584c6dd35, 0x710c87d72fcdb,
                0x58c0d9f497ce8, 0x7f018bd629dcb]),
        xy2d:
            Fe([0x20bd73f9b0c44, 0x066560cfabb58, 0x3b4945ffaefb1,
                0x24f43078c1d67, 0x1b15635774ad4]),
    },
    Niels {
        y_plus_x:
            Fe([0x598ab7cc5b81d, 0x5a178808f56bf, 0x265b5049ed35e,
                0x71e957e581c35, 0x70e17d76341d2]),
        y_minus_x:
            Fe([0x47af78b212a99, 0x009ce3711a643, 0x1630957303f64,
                0x2918d657461e7, 0x6d0a8254b021e]),
        xy2d:
            Fe([0x62d1af44cd3fc, 0x43bfff2b509bd, 0x4b686b46e4c3e,
                0x5d82fc65d0aa8, 0x5f2a8a27f2ef6]),
    },
    Niels {
        y_plus_x:
            Fe([0x4945668bde759, 0x34e116517553c, 0x2e84fa91f53ea,
                0x269d7efb47092, 0x2e5a61c10d5ac]),
        y_minus_x:
            Fe([0x4d1267c780264, 0x474b50b88865c, 0x7fd97efbc02d7,
                0x4554a5db1d823, 0x100ba7961f418]),
        xy2d:
            Fe([0x713c1043ee759, 0x1de781c488eb6, 0x1c7b1f8a01ecb,
                0x0fcfbf25db20f, 0x2e74f7ad1f2ad]),
    },
    Niels {
        y_plus_x:
            Fe([0x6b48c987c6bae, 0x43c34d43b18ac, 0x4ca6bbf3b95c6,
                0x096b779e5788f, 0x0c51804bff37a]),
        y_minus_x:
            Fe([0x391c253daba41, 0x740a7e4f037b6, 0x7b0d6a0dc52af,
                0x0ad3d8a8aa243, 0x2c626c17d7e55]),
        xy2d:
            Fe([0x11f01b5cc8218, 0x0a9d5387d7205, 0x510c3c6f67881,
                0x335daa005c842, 0x7d80d3db710f3]),
    },
    Niels {
        y_plus_x:
            Fe([0x1cb6bbf98b70b, 0x5796a729cee7d, 0x7f8b2c63a31f9,
                0x35ddd89a50c16, 0x4e4029f44abd8]),
        y_minus_x:
            Fe([0x3f8f5b64cbd2b, 0x46cc7e511f284, 0x796ac9b77078d,
                0x330e4678a1f3e, 0x5eede087d1c95]),
        xy2d:
            Fe([0x3485bb4bd9331, 0x4e8119fc7723b, 0x05446dd6af8af,
                0x7cb414c7d701f, 0x1f795377bf155]),
    },
    Niels {
        y_plus_x:
            Fe([0x265dba95a07d8, 0x536a0dcd483cb, 0x7d416f80247c5,
                0x5680e6a63ee0e, 0x6b4067a79c574]),
        y_minus_x:
            Fe([0x3f0cc5ac714ad, 0x2cc7fdf6de726, 0x4087ec63d2017,
                0x267e8922eeed4, 0x261c89c58f3bb]),
        xy2d:
            Fe([0x2b8373f822288, 0x20edd73082c9b, 0x7251eea22c896,
                0x31a7435dfdac9, 0x060b5c1901b87]),
    },
    Niels {
        y_plus_x:
            Fe([0x2120306e495e7, 0x76761d6e3925d, 0x5b480e795b893,
                0x15dc969fa3c9c, 0x530d1d54ebb55]),
        y_minus_x:
            Fe([0x10f115d35368f, 0x4667e52e77a26, 0x19bdd4aca57ae,
                0x588de9a5ed0a5, 0x5390aef7a1e74]),
        xy2d:
            Fe([0x29618d5e4ba43, 0x180380c22c07a, 0x0c2fcbcf6ec9f,
                0x1ead3c3f1f34f, 0x5cc0ad466c851]),
    },
    Niels {
        y_plus_x:
            Fe([0x7d564080bc5bd, 0x4fb6cff342ad0, 0x04c9ae169f477,
                0x3df0bcb628a10, 0x7d6e15a0e6ce2]),
        y_minus_x:
            Fe([0x4828e347ee87b, 0x44beb0081fa9b, 0x49e0fe48231be,
                0x7484b1debacb2, 0x4db882c3b3ac5]),
        xy2d:
            Fe([0x6f4af9c57acfe, 0x24e6eee9f457b, 0x14c60fe4976ee,
                0x027bc95b9d54e, 0x53b6110d8cbd5]),
    },
];

/// The odd multiples of the base point, `B` to `63B`, which the
/// width-7 digits of a verification scalar select.
#[rustfmt::skip]
pub(super) const ODD: [Niels; 32] = [
    Niels {
        y_plus_x:
            Fe([0x493c6f58c3b85, 0x0df7181c325f7, 0x0f50b0b3e4cb7,
                0x5329385a44c32, 0x07cf9d3a33d4b]),
        y_minus_x:
            Fe([0x03905d740913e, 0x0ba2817d673a2, 0x23e2827f4e67c,
                0x133d2e0c21a34, 0x44fd2f9298f81]),
        xy2d:
            Fe([0x11205877aaa68, 0x479955893d579, 0x50d66309b67a0,
                0x2d42d0dbee5ee, 0x6f117b689f0c6]),
    },
    Niels {
        y_plus_x:
            Fe([0x5b0a84cee9730, 0x61d10c97155e4, 0x4059cc8096a10,
                0x47a608da8014f, 0x7a164e1b9a80f]),
        y_minus_x:
            Fe([0x11fe8a4fcd265, 0x7bcb8374faacc, 0x52f5af4ef4d4f,
                0x5314098f98d10, 0x2ab91587555bd]),
        xy2d:
            Fe([0x6933f0dd0d889, 0x44386bb4c4295, 0x3cb6d3162508c,
                0x26368b872a2c6, 0x5a2826af12b9b]),
    },
    Niels {
        y_plus_x:
            Fe([0x2bc4408a5bb33, 0x078ebdda05442, 0x2ffb112354123,
                0x375ee8df5862d, 0x2945ccf146e20]),
        y_minus_x:
            Fe([0x182c3a447d6ba, 0x22964e536eff2, 0x192821f540053,
                0x2f9f19e788e5c, 0x154a7e73eb1b5]),
        xy2d:
            Fe([0x3dbf1812a8285, 0x0fa17ba3f9797, 0x6f69cb49c3820,
                0x34d5a0db3858d, 0x43aabe696b3bb]),
    },
    Niels {
        y_plus_x:
            Fe([0x25cd0944ea3bf, 0x75673b81a4d63, 0x150b925d1c0d4,
                0x13f38d9294114, 0x461bea69283c9]),
        y_minus_x:
            Fe([0x72c9aaa3221b1, 0x267774474f74d, 0x064b0e9b28085,
                0x3f04ef53b27c9, 0x1d6edd5d2e531]),
        xy2d:
            Fe([0x36dc801b8b3a2, 0x0e0a7d4935e30, 0x1deb7cecc0d7d,
                0x053a94e20dd2c, 0x7a9fbb1c6a0f9]),
    },
    Niels {
        y_plus_x:
            Fe([0x6678aa6a8632f, 0x5ea3788d8b365, 0x21bd6d6994279,
                0x7ace75919e4e3, 0x34b9ed338add7]),
        y_minus_x:
            Fe([0x6217e039d8064, 0x6dea408337e6d, 0x57ac112628206,
                0x647cb65e30473, 0x49c05a51fadc9]),
        xy2d:
            Fe([0x4e8bf9045af1b, 0x514e33a45e0d6, 0x7533c5b8bfe0f,
                0x583557b7e14c9, 0x73c172021b008]),
    },
    Niels {
        y_plus_x:
            Fe([0x700848a802ade, 0x1e04605c4e5f7, 0x5c0d01b9767fb,
                0x7d7889f42388b, 0x4275aae2546d8]),
        y_minus_x:
            Fe([0x75b0249864348, 0x52ee11070262b, 0x237ae54fb5acd,
                0x3bfd1d03aaab5, 0x18ab598029d5c]),
        xy2d:
            Fe([0x32cc5fd6089e9, 0x426505c949b05, 0x46a18880c7ad2,
                0x4a4221888ccda, 0x3dc65522b53df]),
    },
    Niels {
        y_plus_x:
            Fe([0x0c222a2007f6d, 0x356b79bdb77ee, 0x41ee81efe12ce,
                0x120a9bd07097d, 0x234fd7eec346f]),
        y_minus_x:
            Fe([0x7013b327fbf93, 0x1336eeded6a0d, 0x2b565a2bbf3af,
                0x253ce89591955, 0x0267882d17602]),
        xy2d:
            Fe([0x0a119732ea378, 0x63bf1ba8e2a6c, 0x69f94cc90df9a,
                0x431d1779bfc48, 0x497ba6fdaa097]),
    },
    Niels {
        y_plus_x:
            Fe([0x6cc0313cfeaa0, 0x1a313848da499, 0x7cb534219230a,
                0x39596dedefd60, 0x61e22917f12de]),
        y_minus_x:
            Fe([0x3cd86468ccf0b, 0x48553221ac081, 0x6c9464b4e0a6e,
                0x75fba84180403, 0x43b5cd4218d05]),
        xy2d:
            Fe([0x2762f9bd0b516, 0x1c6e7fbddcbb3, 0x75909c3ace2bd,
                0x42101972d3ec9, 0x511d61210ae4d]),
    },
    Niels {
        y_plus_x:
            Fe([0x676ef950e9d81, 0x1b81ae089f258, 0x63c4922951883,
                0x2f1d54d9b3237, 0x6d325924ddb85]),
        y_minus_x:
            Fe([0x386484420de87, 0x2d6b25db68102, 0x650b4962873c0,
                0x4081cfd271394, 0x71a7fe6fe2482]),
        xy2d:
            Fe([0x182b8a5c8c854, 0x73fcbe5406d8e, 0x5de3430cff451,
                0x554b967ac8c41, 0x4746c4b6559ee]),
    },
    Niels {
        y_plus_x:
            Fe([0x77b3c6dc69a2b, 0x4edf13ec2fa6e, 0x4e85ad77beac8,
                0x7dba2b28e7bda, 0x5c9a51de34fe9]),
        y_minus_x:
            Fe([0x546c864741147, 0x3a1df99092690, 0x1ca8cc9f4d6bb,
                0x36b7fc9cd3b03, 0x219663497db5e]),
        xy2d:
            Fe([0x0f1cf79f10e67, 0x43ccb0a2b7ea2, 0x05089dfff776a,
                0x1dd84e1d38b88, 0x4804503c60822]),
    },
    Niels {
        y_plus_x:
            Fe([0x49ed02ca37fc7, 0x474c2b5957884, 0x5b8388e816683,
                0x4b6c454b76be4, 0x553398a516506]),
        y_minus_x:
            Fe([0x021d23a36d175, 0x4fd3373c6476d, 0x20e291eeed02a,
                0x62f2ecf2e7210, 0x771e098858de4]),
        xy2d:
            Fe([0x2f5d278451edf, 0x730b133997342, 0x6965420eb6975,
                0x308a3bfa516cf, 0x5a5ed1d68ff5a]),
    },
    Niels {
        y_plus_x:
            Fe([0x5122afe150e83, 0x4afc966bb0232, 0x1c478833c8268,
                0x17839c3fc148f, 0x44acb897d8bf9]),
        y_minus_x:
            Fe([0x5e0c558527359, 0x3395b73afd75c, 0x072afa4e4b970,
                0x62214329e0f6d, 0x019b60135fefd]),
        xy2d:
            Fe([0x068145e134b83, 0x1e4860982c3cc, 0x068fb5f13d799,
                0x7c9283744547e, 0x150c49fde6ad2]),
    },
    Niels {
        y_plus_x:
            Fe([0x3f29509471138, 0x729eeb4ca31cf, 0x69c22b575bfbc,
                0x4910857bce212, 0x6b2b5a075bb99]),
        y_minus_x:
            Fe([0x1863c9cdca868, 0x3770e295a1709, 0x0d85a3720fd13,
                0x5e0ff1f71ab06, 0x78a6d7791e05f]),
        xy2d:
            Fe([0x7704b47a0b976, 0x2ae82e91aab17, 0x50bd6429806cd,
                0x68055158fd8ea, 0x725c7ffc4ad55]),
    },
    Niels {
        y_plus_x:
            Fe([0x26715d1cf99b2, 0x2205441a69c88, 0x448427dcd4b54,
                0x1d191e88abdc5, 0x794cc9277cb1f]),
        y_minus_x:
            Fe([0x02bf71cd098c0, 0x49dabcc6cd230, 0x40a6533f905b2,
                0x573efac2eb8a4, 0x4cd54625f855f]),
        xy2d:
            Fe([0x6c426c2ac5053, 0x5a65ece4b095e, 0x0c44086f26bb6,
                0x7429568197885, 0x7008357b6fcc8]),
    },
    Niels {
        y_plus_x:
            Fe([0x0672738773f01, 0x752bf799f6171, 0x6b4a6dae33323,
                0x7b54696ead1dc, 0x06ef7e9851ad0]),
        y_minus_x:
            Fe([0x39fbb82584a34, 0x47a568f257a03, 0x14d88091ead91,
                0x2145b18b1ce24, 0x13a92a3669d6d]),
        xy2d:
            Fe([0x3771cc0577de5, 0x3ca06bb8b9952, 0x00b81c5d50390,
                0x43512340780ec, 0x3c296ddf8a2af]),
    },
    Niels {
        y_plus_x:
            Fe([0x515f9d914a713, 0x73191ff2255d5, 0x54f5cc2a4bdef,
                0x3dd57fc118bcf, 0x7a99d393490c7]),
        y_minus_x:
            Fe([0x34d2ebb1f2541, 0x0e815b723ff9d, 0x286b416e25443,
                0x0bdfe38d1bee8, 0x0a892c7007477]),
        xy2d:
            Fe([0x2ed2436bda3e8, 0x02afd00f291ea, 0x0be7381dea321,
                0x3e952d4b2b193, 0x286762d28302f]),
    },
    Niels {
        y_plus_x:
            Fe([0x036093ce35b25, 0x3b64d7552e9cf, 0x71ee0fe0b8460,
                0x69d0660c969e5, 0x32f1da046a9d9]),
        y_minus_x:
            Fe([0x58e2bce2ef5bd, 0x68ce8f78c6f8a, 0x6ee26e39261b2,
                0x33d0aa50bcf9d, 0x7686f2a3d6f17]),
        xy2d:
            Fe([0x512a66d597c6a, 0x0609a70a57551, 0x026c08a3c464c,
                0x4531fc8ee39e1, 0x561305f8a9ad2]),
    },
    Niels {
        y_plus_x:
            Fe([0x4978dec92aed1, 0x069adae7ca201, 0x11ee923290f55,
                0x69641898d916c, 0x00aaec53e35d4]),
        y_minus_x:
            Fe([0x2cc28e7b0c0d5, 0x77b60eb8a6ce4, 0x4042985c277a6,
                0x636657b46d3eb, 0x030a1aef2c57c]),
        xy2d:
            Fe([0x1f773003ad2aa, 0x005642cc10f76, 0x03b48f82cfca6,
                0x2403c10ee4329, 0x20be9c1c24065]),
    },
    Niels {
        y_plus_x:
            Fe([0x387d8249673a6, 0x5bea8dc927c2a, 0x5bd8ed5650ef0,
                0x0ef0e3fcd40e1, 0x750ab3361f0ac]),
        y_minus_x:
            Fe([0x0e44ae2025e60, 0x5f97b9727041c, 0x5683472c0ecec,
                0x188882eb1ce7c, 0x69764c545067e]),
        xy2d:
            Fe([0x23283a2f81037, 0x477aff97e23d1, 0x0b8958dbcbb68,
                0x0205b97e8add6, 0x54f96b3fb7075]),
    },
    Niels {
        y_plus_x:
            Fe([0x5f20429669279, 0x08fafae4941f5, 0x15d83c4eb7688,
                0x1cf379eca4146, 0x3d7fe9c52bb75]),
        y_minus_x:
            Fe([0x5afc616b11ecd, 0x39f4aec8f22ef, 0x3b39e1625d92e,
                0x5f85bd4508873, 0x78e6839fbe85d]),
        xy2d:
            Fe([0x32df737b8856b, 0x0608342f14e06, 0x3967889d74175,
                0x1211907fba550, 0x70f268f350088]),
    },
    Niels {
        y_plus_x:
            Fe([0x64583b1805f47, 0x22c1baf832cd0, 0x132c01bd4d717,
                0x4ecf4c3a75b8f, 0x7c0d345cfad88]),
        y_minus_x:
            Fe([0x4112070dcf355, 0x7dcff9c22e464, 0x54ada60e03325,
                0x25cd98eef769a, 0x404e56c039b8c]),
        xy2d:
            Fe([0x71f4b8c78338a, 0x62cfc16bc2b23, 0x17cf51280d9aa,
                0x3bbae5e20a95a, 0x20d754762aaec]),
    },
    Niels {
        y_plus_x:
            Fe([0x7c36fc73bb758, 0x4a6c797734bd1, 0x0ef248ab3950e,
                0x63154c9a53ec8, 0x2b8f1e46f3cee]),
        y_minus_x:
            Fe([0x4feb135b9f543, 0x63bd192ad93ae, 0x44e2ea612cdf7,
                0x670f4991583ab, 0x38b8ada8790b4]),
        xy2d:
            Fe([0x04a9cdf51f95d, 0x5d963fbd596b8, 0x22d9b68ace54a,
                0x4a98e8836c599, 0x049aeb32ceba1]),
    },
    Niels {
        y_plus_x:
            Fe([0x07d0b75fc7931, 0x16f4ce4ba754a, 0x5ace4c03fbe49,
                0x27e0ec12a159c, 0x795ee17530f67]),
        y_minus_x:
            Fe([0x67d3c63dcfe7e, 0x112f0adc81aee, 0x53df04c827165,
                0x2fe5b33b430f0, 0x51c665e0c8d62]),
        xy2d:
            Fe([0x25b0a52ecbd81, 0x5dc0695fce4a9, 0x3b928c575047d,
                0x23bf3512686e5, 0x6cd19bf49dc54]),
    },
    Niels {
        y_plus_x:
            Fe([0x6612165afc386, 0x1171aa36203ff, 0x2642ea820a8aa,
                0x1f3bb7b313f10, 0x5e01b3a7429e4]),
        y_minus_x:
            Fe([0x7619052179ca3, 0x0c16593f0afd0, 0x265c4795c7428,
                0x31c40515d5442, 0x7520f3db40b2e]),
        xy2d:
            Fe([0x50be3d39357a1, 0x3ab33d294a7b6, 0x4c479ba59edb3,
                0x4c30d184d326f, 0x71092c9ccef3c]),
    },
    Niels {
        y_plus_x:
            Fe([0x3d8ac74051dcf, 0x10ab6f543d0ad, 0x5d0f3ac0fda90,
                0x5ef1d2573e5e4, 0x4173a5bb7137a]),
        y_minus_x:
            Fe([0x0523f0364918c, 0x687f56d638a7b, 0x20796928ad013,
                0x5d38405a54f33, 0x0ea15b03d0257]),
        xy2d:
            Fe([0x56e31f0f9218a, 0x5635f88e102f8, 0x2cbc5d969a5b8,
                0x533fbc98b347a, 0x5fc565614a4e3]),
    },
    Niels {
        y_plus_x:
            Fe([0x2e1e67790988e, 0x1e38b9ae44912, 0x648fbb4075654,
                0x28df1d840cd72, 0x3214c7409d466]),
        y_minus_x:
            Fe([0x6570dc46d7ae5, 0x18a9f1b91e26d, 0x436b6183f42ab,
                0x550acaa4f8198, 0x62711c414c454]),
        xy2d:
            Fe([0x1827406651770, 0x4d144f286c265, 0x17488f0ee9281,
                0x19e6cdb5c760c, 0x5bea94073ecb8]),
    },
    Niels {
        y_plus_x:
            Fe([0x0ce63f343d2f8, 0x1e0a87d1e368e, 0x045edbc019eea,
                0x6979aed28d0d1, 0x4ad0785944f1b]),
        y_minus_x:
            Fe([0x5bf0912c89be4, 0x62fadcaf38c83, 0x25ec196b3ce2c,
                0x77655ff4f017b, 0x3aacd5c148f61]),
        xy2d:
            Fe([0x63b34c3318301, 0x0e0e62d04d0b1, 0x676a233726701,
                0x29e9a042d9769, 0x3aff0cb1d9028]),
    },
    Niels {
        y_plus_x:
            Fe([0x6430bf4c53505, 0x264c3e4507244, 0x74c9f19a39270,
                0x73f84f799bc47, 0x2ccf9f732bd99]),
        y_minus_x:
            Fe([0x5c7eb3a20405e, 0x5fdb5aad930f8, 0x4a757e63b8c47,
                0x28e9492972456, 0x110e7e86f4cd2]),
        xy2d:
            Fe([0x0d89ed603f5e4, 0x51e1604018af8, 0x0b8eedc4a2218,
                0x51ba98b9384d0, 0x05c557e0b9693]),
    },
    Niels {
        y_plus_x:
            Fe([0x6bbb089c20eb0, 0x6df41fb0b9eee, 0x51087ed87e16f,
                0x102db5c9fa731, 0x289fef0841861]),
        y_minus_x:
            Fe([0x1ce311fc97e6f, 0x6023f3fb5db1f, 0x7b49775e8fc98,
                0x3ad70adbf5045, 0x6e154c178fe98]),
        xy2d:
            Fe([0x16336fed69abf, 0x4f066b929f9ec, 0x4e9ff9e6c5b93,
                0x18c89bc4bb2ba, 0x6afbf642a95ca]),
    },
    Niels {
        y_plus_x:
            Fe([0x55070f913a8cc, 0x765619eac2bbc, 0x3ab5225f47459,
                0x76ced14ab5b48, 0x12c093cedb801]),
        y_minus_x:
            Fe([0x0de0c62f5d2c1, 0x49601cf734fb5, 0x6b5c38263f0f6,
                0x4623ef5b56d06, 0x0db4b851b9503]),
        xy2d:
            Fe([0x47f9308b8190f, 0x414235c621f82, 0x31f5ff41a5a76,
                0x6736773aab96d, 0x33aa8799c6635]),
    },
    Niels {
        y_plus_x:
            Fe([0x0f588fc156cb1, 0x363414da4f069, 0x7296ad9b68aea,
                0x4d3711316ae43, 0x212cd0c1c8d58]),
        y_minus_x:
            Fe([0x7f51ebd085cf2, 0x12cfa67e3f5e1, 0x1800cf1e3d46a,
                0x54337615ff0a8, 0x233c6f29e8e21]),
        xy2d:
            Fe([0x4d5107f18c781, 0x64a4fd3a51a5e, 0x4f4cd0448bb37,
                0x671d38543151e, 0x1db7778911914]),
    },
    Niels {
        y_plus_x:
            Fe([0x14769dd701ab6, 0x28339f1b4b667, 0x4ab214b8ae37b,
                0x25f0aefa0b0fe, 0x7ae2ca8a017d2]),
        y_minus_x:
            Fe([0x352397c6bc26f, 0x18a7aa0227bbe, 0x5e68cc1ea5f8b,
                0x6fe3e3a7a1d5f, 0x31ad97ad26e2a]),
        xy2d:
            Fe([0x017ed0920b962, 0x187e33b53b6fd, 0x55829907a1463,
                0x641f248e0a792, 0x1ed1fc53a6622]),
    },
];
