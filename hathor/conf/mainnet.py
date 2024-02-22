# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from hathor.checkpoint import Checkpoint as cp
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.settings import Settings as FeatureActivationSettings

SETTINGS = HathorSettings(
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    NETWORK_NAME='mainnet',
    BOOTSTRAP_DNS=['mainnet.hathor.network'],
    ENABLE_PEER_WHITELIST=True,
    WHITELIST_URL='https://hathor-public-files.s3.amazonaws.com/whitelist_peer_ids',
    # Genesis stuff
    # output addr: HJB2yxxsHtudGGy3jmVeadwMfRi2zNCKKD
    GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a9147fd4ae0e4fb2d2854e76d359029d8078bb99649e88ac'),
    GENESIS_BLOCK_TIMESTAMP=1578075305,
    GENESIS_BLOCK_NONCE=2591358,
    GENESIS_BLOCK_HASH=bytes.fromhex('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc'),
    GENESIS_TX1_NONCE=7715,
    GENESIS_TX1_HASH=bytes.fromhex('0002d4d2a15def7604688e1878ab681142a7b155cbe52a6b4e031250ae96db0a'),
    GENESIS_TX2_NONCE=3769,
    GENESIS_TX2_HASH=bytes.fromhex('0002ad8d1519daaddc8e1a37b14aac0b045129c01832281fb1c02d873c7abbf9'),
    CHECKPOINTS=[
        cp(100_000, bytes.fromhex('0000000000001247073138556b4f60fff3ff6eec6521373ccee5a6526a7c10af')),
        cp(200_000, bytes.fromhex('00000000000001bf13197340ae0807df2c16f4959da6054af822550d7b20e19e')),
        cp(300_000, bytes.fromhex('00000000000000e1e8bdba2006cc34db3a1f20294cbe87bd52cceda245238290')),
        cp(400_000, bytes.fromhex('000000000000002ae98f2a15db331d059eeed34d71f813f51d1ac1dbf3d94089')),
        cp(500_000, bytes.fromhex('00000000000000036f2f7234f7bf83b5746ce9b8179922d2781efd82aa3d72bf')),
        cp(600_000, bytes.fromhex('0000000000000001ad38d502f537ce757d7e732230d22434238ca215dd92cca1')),
        cp(700_000, bytes.fromhex('000000000000000066f04be2f3a8607c1c71682e65e07150822fb03afcbf4035')),
        cp(800_000, bytes.fromhex('0000000000000000958372b3ce24a26ce97a3b063c835e7d55c632f289f2cdb0')),
        cp(900_000, bytes.fromhex('0000000000000000c9bac3c3c71a1324f66481be03ad0e5d5fbbed94fc6b8794')),
        cp(1_000_000, bytes.fromhex('00000000000000001060adafe703b8aa28c7d2cfcbddf77d52e62ea0a1df5416')),
        cp(1_100_000, bytes.fromhex('00000000000000000ecc349992158a3972e7a24af494a891a8d1ae3ab982ee4e')),
        cp(1_200_000, bytes.fromhex('000000000000000091ddabd35a0c3984609e2892b72b14d38d23d58e1fa87c91')),
        cp(1_300_000, bytes.fromhex('00000000000000000244794568649ac43e0abd4b53b1a583b6cc8e243e65f582')),
        cp(1_400_000, bytes.fromhex('000000000000000011a65b1c3cba2b94ad05525ac2ec60f315bb7b204c8160c7')),
        cp(1_500_000, bytes.fromhex('0000000000000000ddbbf005a3970f256ad46167fc2143796d8f87c0c905e657')),
        cp(1_600_000, bytes.fromhex('00000000000000011098dda3dbe2ac95287ec0f3c12edc5c054dd8edc70cd6c3')),
        cp(1_700_000, bytes.fromhex('000000000000000054278ce817fda6cd3287144545babf0a415f883d074601ab')),
        cp(1_800_000, bytes.fromhex('00000000000000002110c5ccb781bee9fea0a4cbbd49e52023ffb5900732ee4d')),
        cp(1_900_000, bytes.fromhex('000000000000000032a8f2411190e1e49ff577d352950011083b85d935453338')),
        cp(2_000_000, bytes.fromhex('000000000000000005c31cc418e95497dbb2017a6ae2683a1550bd61f180b5b1')),
        cp(2_100_000, bytes.fromhex('00000000000000000c96c02d514017263d4e624a61fb9f10babcbf8d4632b67b')),
        cp(2_200_000, bytes.fromhex('00000000000000001016a7bbb6ccfc957ba6d29a562b43e8620f57ddc9147dde')),
        cp(2_300_000, bytes.fromhex('0000000000000000164dafd8d922c783a99d83f66220eb7c54f11bee1aaac126')),
        cp(2_400_000, bytes.fromhex('0000000000000000067aa4bf7306dadf0f56e38380327a472f55e7be72fbe7da')),
        cp(2_500_000, bytes.fromhex('00000000000000000c418b03ceb3a4fe7023674811f8ec94d7b9d5b1879ddc28')),
        cp(2_600_000, bytes.fromhex('0000000000000000020af703e2955e3f7934e8bc376da2ba6cfc6dc609feaf84')),
        cp(2_700_000, bytes.fromhex('00000000000000000cf3a35ab01a2281024ca4ca7871f5a6d67106eb36151038')),
        cp(2_800_000, bytes.fromhex('000000000000000004439733fd419a8a747e8afe2f89348a17c1fac24538a63c')),
        cp(2_900_000, bytes.fromhex('0000000000000000090cbd5a7958c82a2b969103001d92334f287dadcf3e01bc')),
        cp(3_000_000, bytes.fromhex('000000000000000013c9086f4ce441f5db5de55a5e235f4f7f1ef223aedfe2db')),
        cp(3_100_000, bytes.fromhex('00000000000000000d226a5998ffc65af89b1226126b1af1f8d0712a5301c775')),
        cp(3_200_000, bytes.fromhex('0000000000000000028d9629d85d93d0f5e798a498ca7b1710ffc157fa045cd5')),
        cp(3_300_000, bytes.fromhex('0000000000000000065b74441acb3d2ff770d384b2bad44c9823f26a0327690c')),
        cp(3_400_000, bytes.fromhex('000000000000000077242c961a0c6f708bc671a8372eb8b095311f091fddc6c3')),
        cp(3_500_000, bytes.fromhex('000000000000000a34ba20552c3cae9549b9c5ca07f644cf005328c948aa54d8')),
        cp(3_600_000, bytes.fromhex('000000000000000011031d9ff030cd9e6fe8a3766bbeda6f6337c40dd30fa65f')),
    ],
    SOFT_VOIDED_TX_IDS=list(map(bytes.fromhex, [
        '0000000012a922a6887497bed9c41e5ed7dc7213cae107db295602168266cd02',
        '000000001980b413ad5b5c5152338093aecfb1f5a7563d4e7fef8fb240a50bb9',
        '000000001bf05ea882891c99e5285f38e001f10226380a830168d8070c21b78c',
        '0000000024e0320e4dd6990299f083db2448c9f200223cad8ac23c282fd4c80e',
        '000000002767852b0eaca53a0f91db8202bea171c0d060fca4ae1030fd2a2e7a',
        '000000002875eff18af64f50481bc7576224572da7d63a43e994110b0002f6b7',
        '000000003e888a6a898a59c569ed839d047e5490554b132b2a3fd96bca8a8166',
        '0000000042ecfa3e98251eb56a8c19f6914b8cd275bcd49c1c84f9fc28123207',
        '0000000051c62be84b273ac17bba34426c654464eff7b7563208c4a3a2582fb6',
        '0000000058738ab486ec8da130e394361cb78fb331c5b5adf11798e046d89f08',
        '00000000818f72870b4df1961e8b81daacc00283490758c3ef6741245116e6ad',
        '00000000998bacf9dfc135233f83127a01ad61f5707955f4e0d0d12c80e85f2e',
        '00000000b733604d8afdf8102b7dcf9a29605312c0466f98f5183213c4e1d327',
        '00000000c57350f31fa1b09af55a6ea722867a596b5f5b408c541bfaec38fd8f',
        '00000000c58405f10e5a19f46295f08cb3c9d3e0479ff7ff418b9ad5e2c074d4',
        '00000000c780100a67213a1cf726f57bfd02e4d7e673b24693e40dab1eabc372',
        '00000000d7dbc1e0b99d6940561ddd9b99fa2f51fde82ea343156f90daa0fa0a',
        '00000000f44f6785caca715698bafe9a60895bb6675579b0c33f6b45330a538c',
        '00000017df9acb795a358e8a6c1afde3ac0d3dfd6241441320b9449fdd27534d',
        '00000042d700981477caec92d78861bac49ef72d8d54dbaf6fbc316025563f93',
        '000000a56b177bfc6d3b83c351cb99cba665898c029f7bb628d36bdc9a3053cc',
        '000000ac12f9c538404cc8b44f28e6354f76740d0daf206755f74c5b8bcc660a',
        '000000b2af584901b731c4d2d6207a531ce3f4447c6470de9c0b189fe2cd616e',
        '000000d133f2710bafd4d8b63b81081f629cf34ebcaa70ed44243a014ed85a1a',
        '000000dc6c899e76793bceab54ceb124138ab9fc447f01a3beea3f4dd0549186',
        '000000ebf1b6246ac0f859f4e88544a51b71ca6a8e3573149b34e06903aec338',
        '000000eda13cf4e1b33b8ff3c62b892e6c4e9c05e865173123283984424de827',
        '000000f1dc1476e3921a782d3cd815aec3b7b68723d0b9599fbd99fc9a7057ee',
        '000000ffb042976e52200535299f5a4cc13805949d6c233adf8bf26401403506',
        '0000011e8f0ff3a741a48bcc49acce5680d593cf1c69d39aaf667c1dd2f850a7',
        '00000128fce693d2c3642d9c906def03049600c48252089e5d649e992f9a0542',
        '0000013cf9daed1138f88829117d36ce59e231fde8b724d715af190266b322c8',
        '000001521fd0530e6e67e122bd0454dc1a62f8687539bf3b4adf2e84306a4a6d',
        '0000016617061d62979146812c422a52f381b3fd48e3fbcdc6962d7ef86f73f6',
        '000001664d4736d66c0fcd4241e0166103f7569eed2150f86bc0c7c65c063d80',
        '000001a87ca6db997b56837df35d70fcab3960e7ff0c0385d1aa455931ed55bd',
        '000001c2ddc22637d06ba993b253b05dc94cf4c7d835b961e7741543a584e395',
        '000001c90db53e28c8f012c752591ccb7e755a74c86a655a2900e0bd3a7d0ecc',
        '000001cf28c56059e3b4516eb0c8839b981940df0c9cb3066a5ad0ae5944c4a5',
        '000001e6967e87d4cca6fda912458b3eb51f74409d12be997b8a84f02b20218d',
        '000001f6e130f3291548f8a1164a252f2b229cce2629647e60393ef31e4d483c',
        '000001f78b3e0ca9d36a7354bd9fadea960f89536afc258e62f0fa544204405d',
        '0000020857d6a0d3291bda650f4c8f85c073613641f121da48c2debf26d72884',
        '000002089edd265c5b50d6ceb3eb862c2fffaff269ca4b7a024579cd44ccfe42',
        '0000020a48625f27ce380fde59b5e3dfd4204e31f400b2d5959262dbf47b5dc6',
        '0000020c2ed05a4c23f89fc9de4b8bb6f93d86b798156fbd8e0abf06c8711ac0',
        '00000212fbda0a12653e5298b44a7c3795f51a0eeb379aa660a7a30903c67cc8',
        '000002187a0b41ee345cff15e9c914a84573e3dcdb71b55f3f44ab55e603da92',
        '00000222f01c219470806f8866f97d73a467bd4cfe3af2eee82bddc4f5e80a17',
        '0000023444fb134782db2462a6a0b810ce8b31041de539d0cb3c96b33107af99',
        '0000023464ecb9218d4d21a9397fbf22b49820af65c6b07d1e56fe7cf15baed7',
        '0000023bcf6f92885339c3a8fbb55e2c4f220241de18e6666d217ba04b238cd3',
        '00000241f25d2f75e657b507feba5d6d3819644f257db4bc1054c5f72c83b8a7',
        '00000258411bdb0d128ebfc9b127c039ee4317e0f95e76dda9a9170ea877d25b',
        '00000259b49387008617b5a0f86ecea8e615268e741db774ee34d0fb23857926',
        '0000025a334e8ff3d96f1a209119a2960f61017c29f7f9742618add01df9c82c',
        '000002907cfd7fbad44c098ba2d414b7ab366f9c52d56781c59fb4633a724c00',
        '00000293f88193d7793c8c9259c661969d2261402baadfa3cb48e83aab08ae3b',
        '000002aa2d6dbfc9044c829ec83c9b3e5f07aad875af51b5589410510f2517d7',
        '000002af16219be350b1e278f61043649733d179037be495885f056f798cb526',
        '000002b677ffe2cd16e8d4b28608f4b2eaf918924431cd97ec3eae3659a1f19c',
        '000002c0ab260e7cf4b5a31fbed03c1efbc0b656edb561c6727e1357106a33b8',
        '00000353b3fd1550bbb87329a0058261093970f7974db037f4c6185d43b2bed4',
        '0000037c0f10cca87577100b5f7bc2b8100e62f6facf83ccd29e3f6ba280afcd',
        '0000039f312e0bbd3fe3c02ce94c56d895cc8c87208176a2e7673ebfc72c9e8b',
        '000003a6a42a0fef94fa689f4ea03bbf563a1e82a4626a7d833d85aef0f975f5',
        '000003a8ba8ea4e8fa72762c69923643e2a66a1980ad3d0f25ba279bed48d1a7',
        '000003b7d6d3c005e9a4027a6722a6d923b7ddbe2b7add31888ae280200f3e0d',
        '000003baa91af94d28e7032327324c458cb4016b10e87c6adf4884eaf9598629',
        '000003bb5d47addfa303836320c3fd292daede501a57b010afc4a52c6c216586',
        '000003c16d094663db2528cd37f635ed28095dabde60ca70d01c76e3c8388995',
        '000003c60b7fd804b161d53138b15bc266ea62ba1770ea6733242a9413a15fe5',
        '000003d19ba2638271c5edf5bf1e633e808ca52cb753104ec0254ba09e749d89',
        '000003fb91f0e962e96025903c3c3aaffe51c477f7c1c49e4fd161d7ee501ba1',
        '000004167295adf699bf3bb99a87bbfa20b491779432f8e1e409f11731b355e4',
        '000004351d74e5dfbb9d1010e8fc857b3456ecba38ef3d7b5844435125de364e',
        '0000046901e90282e1ea707bc8b3ba3f57573038e6031d5bb17103f69716137a',
        '0000046e0e8ab1295064861af24dc92ba93fe359dae0995fa8e7674183779f4f',
        '00000479f2fcb4caeb2752909a3ac160681ad923b10f8cf884b798f56916bba8',
        '000004a4b36e1abc71ecd71ca89190ebed895892708577c181a2910a49f08cfa',
        '0000051bacbd74bf190857ffd7c035e54f67488c78e2fb6f9c1c83980ad71bef',
        '0000058e17aa5303e022572b40482dc2661059da4f5be95e7dde22750d1f2ff0',
        '000005cd2a6a49a6994daa2f3d0ba6e0fb881284954b29b57401050f3ca47bdf',
        '000005fd618bf0c520447a5518627abe5f47e90248030d965df48a35207e33fb',
        '0000060426306faf8b1e772bc9968d610fbc6684435d2de996621f958b97d64a',
        '000006b56ac7e1ea911210f7eb4db397a61bb0d5a8580821fdaa1abb7602de9c',
        '00000713e01f81308ed02309d4bbb6a36664ff3f10f587a6879ec753c7802e23',
        '000007683cd8d775d309e07308f7c9125e621cebb72aeb8ec1d710e0810157ea',
        '00000914c20126cf00fffb71d0af7a03cf17ddda69ecc5bd68abc127090c95d3',
        '00000b310fdcf52c9195422d2fcf49ae3de214501261b29a985d8e64bed64fea',
        '00000bd6e23c43367ef5d7bb1e2f0ef4ed9256fa9c5f4f2c737a479f264cf8a0',
        '00000cf6bc737c42ecc7f2fcf92ea4dc92e59404b93b3fa3e1e0648cafb3f4ad',
        '00000ddd6cc76f17a982e506a64f1edb75b89a576ef7b595c11b78d1ef2d68b7',
        '00000e16526da07de7d14bd87155887624069bc67244098fab4f05589f0c5723',
        '00000ea977c8193be1f7abb703e12867e6cf981567699954b8bf7cd1f33094f1',
        '000010c880b068126f3b9d33c4705bcf91a15f80c8c0ee519b232b51ea5697aa',
        '000010fdf4a3e2f60a376180bbb473a280e88d184c13af0aabf6867c07f436af',
        '000016eaffd25d3335523b15bd18ca707b5503a00fed1c39857b20e3227edaf0',
        '00001714c55b80d90489005c3edd8de1779a8b9e2aaf9c56592e5922a8de8ae1',
        '00001958f73bfdbe2cba49a2d6b5221d8046f5326bff67eb37efed70eb103cee',
        '000019a02ba2f7f15cf4abb885f909400e9be7526c033b8ef475fa2dfebf57e3',
        '00001a20cd1ce1b3a021d3a3224dc5c18550b7981508bd446f03a5762724a9e1',
        '00001a40d2ac32d5f39d51680538a72570c9d263eb3ea364cefab7b9906a0e90',
        '00001bd841e1373f711d44a83584125db5cb4844d7086d7981ea91ea78d01183',
        '00001c9fc462dccec2830b0fc87a6d740d03ef92133570d492c558de1d6156bf',
        '00001d1830d70992ff544914fb8fea3d71b8a686e9b466450f6800a2383394f5',
        '000024051364ef7173995581740f448125fb8a215f97065b73cb3fadbcdb885a',
        '000024453eb58e2f0ace673df99ee9b53825a078255dcd0971ea8c4cefa782ff',
        '0000291f0dff2025dd5ade362cc7b8a991a631821e87bdf7b732b5bfedd55507',
        '0000294369e45c257715c5bac9f8e714e97413cbcfd58d2fd26cef6fe39aba64',
        '00002a147679a0cb6d2a3d33fb5d44418bdef1af0bc7630291bac709f41d8567',
        '00002c3d04975c2a1166e115e93cf8d63df5900adf7105cc70ab7a13e8baadca',
        '00002d82c41a430f89cf4e7d4c524143e57e93ee4c73c16daacdab7d79d28e48',
        '00002d9b1ec90c02749c9acceca9e919d523237cef864ec29ab334777b80c226',
        '00002fec62ae183501b05a9c272c7534bf96c78e9a8d237215121cd56ec5cab2',
        '0000302581088e4717d680662c4a9ae07d8e0727f040ec127953c371ea32ea77',
        '0000336ff31ea3e1717c0b02619bc2d09ead38089f298bef179f4b6715eae1f6',
        '000035d96f815ee188b740b4b351279e13d99a89e227393b3f25074d59fbcb8c',
        '00003de89f0752a6a8cd127250c624ff431975c559934ee532c76dcd899c2e66',
        '00003e5372eb70089919c4a6ef7c54e4618c7ac59e16b76b8b5b5e448717ff9a',
        '00003f99d7f877d384b0de992d7e2a8d8aaae685fd25f1819b4ee25c9b913d03',
        '000040db8e91bcdc1e65bc868e904345396a0bc4eb084694a72dbcc485555d80',
        '00004305882eb3eef6b45f025ff58eb7baa5ca35f7d6f42c8b085482b00474e6',
        '000045ecbab77c9a8d819ff6d26893b9da2774eee5539f17d8fc2394f82b758e',
    ])),
    FEATURE_ACTIVATION=FeatureActivationSettings(
        features={
            Feature.NOP_FEATURE_1: Criteria(
                bit=0,
                start_height=4_213_440,  # N
                timeout_height=4_253_760,  # N + 2 * 20160 (2 weeks after the start)
                minimum_activation_height=4_273_920,  # N + 3 * 20160 (3 weeks after the start)
                lock_in_on_timeout=False,
                version='0.59.0',
                signal_support_by_default=True,
            ),
            Feature.NOP_FEATURE_2: Criteria(
                bit=1,
                start_height=4_213_440,  # N
                timeout_height=4_253_760,  # N + 2 * 20160 (2 weeks after the start)
                minimum_activation_height=0,
                lock_in_on_timeout=False,
                version='0.59.0',
                signal_support_by_default=False,
            ),
            Feature.NOP_FEATURE_3: Criteria(
                bit=2,
                start_height=4_273_920,  # N (on 2024/02/22, the best block is 4_251_000 on mainnet)
                timeout_height=4_475_520,  # N + 10 * 20160 (10 weeks after the start)
                minimum_activation_height=4_495_680,  # N + 11 * 20160 (11 weeks after the start)
                lock_in_on_timeout=False,
                version='0.59.0',
                signal_support_by_default=True,
            ),
            Feature.NOP_FEATURE_4: Criteria(
                bit=3,
                start_height=4_273_920,  # N (on 2024/02/22, the best block is 4_251_000 on mainnet)
                timeout_height=4_475_520,  # N + 10 * 20160 (10 weeks after the start)
                minimum_activation_height=0,
                lock_in_on_timeout=False,
                version='0.59.0',
                signal_support_by_default=False,
            ),
        }
    )
)
