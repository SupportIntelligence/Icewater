import "hash"

rule m3f9_1910b2cbc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.1910b2cbc6620b12"
     cluster="m3f9.1910b2cbc6620b12"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hiqaau yqgi shifu"
     md5_hashes="['2fbe02a513edba238636c9a54f801301', '54de996b39a28b695b68ca21b28315cd', 'ac0ebfc858aacd8ae2254be921f99377']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(122368,1195) == "c5f92e741e1e8122dbab09e1d8447606"
}

