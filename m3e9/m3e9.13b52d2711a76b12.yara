import "hash"

rule m3e9_13b52d2711a76b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b52d2711a76b12"
     cluster="m3e9.13b52d2711a76b12"
     cluster_size="117 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="lethic gepys zbot"
     md5_hashes="['b92428546eea40af51d61cfbf85f241f', 'dbe22bdc2202d1dae75d2dd5668343ba', 'a624814f5cb3739494ceeb509784555e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45056,1536) == "f7e2e8ff21aec20aad4e4a91e5e80937"
}

