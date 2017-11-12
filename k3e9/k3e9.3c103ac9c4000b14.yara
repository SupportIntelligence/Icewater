import "hash"

rule k3e9_3c103ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c103ac9c4000b14"
     cluster="k3e9.3c103ac9c4000b14"
     cluster_size="106 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy simbot backdoor"
     md5_hashes="['71ff86258c877c27f5c24b82cc5834b2', '2fadf2036d0b2d7dec7b9c8e6c7f5072', 'b228464af9bda446dd5ff54a9df85b0f']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

