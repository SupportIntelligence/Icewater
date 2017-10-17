import "hash"

rule m3e9_6d14dee9c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d14dee9c6000b12"
     cluster="m3e9.6d14dee9c6000b12"
     cluster_size="779 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi swisyn abzf"
     md5_hashes="['17d6a6a22932340761e92ca83dcb3684', 'a826451f8d0a3a6d0fa068455e337b9b', '35dd21d6e38ece3cac5f1e1ed61a3e94']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8192,1024) == "9f712feaffef3b90b4425924542b4546"
}

