import "hash"

rule k3e9_16a91db946201114
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.16a91db946201114"
     cluster="k3e9.16a91db946201114"
     cluster_size="43 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy rubinurd small"
     md5_hashes="['669032246a3c69ee41470b6276287a2a', 'e86475f6b9d4d0ca597f67221a184bf3', 'cb2fc4871d7e4586e7a5b4e3ca0db3c7']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(12288,1024) == "2b75e03ba80408ac5917d1e4af2d3085"
}

