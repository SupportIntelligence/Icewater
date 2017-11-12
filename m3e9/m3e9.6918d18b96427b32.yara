import "hash"

rule m3e9_6918d18b96427b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6918d18b96427b32"
     cluster="m3e9.6918d18b96427b32"
     cluster_size="14099 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt symmi vbcrypt"
     md5_hashes="['029ca2b91b0a91e494087108e60e1eb9', '05a82b378d15a20c93376fca539d77a8', '05f4bca5e1a5129069b45b8cacbb4f45']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(30720,1024) == "e31ffb95dbbc4d11a42ea0823f11c556"
}

