import "hash"

rule m3e9_16db5468de8bdb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db5468de8bdb16"
     cluster="m3e9.16db5468de8bdb16"
     cluster_size="44 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup lethic zbot"
     md5_hashes="['c50148b6dd3d62355f6cc5f57b50b596', 'e018233913bd5c26f9cc9c78873c39d9', 'ebbf84c70504ca61443fad3c6490f5d1']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(27478,1194) == "0c7a3b0c457592ae628db3ccebba4a1f"
}

