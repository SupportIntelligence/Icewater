import "hash"

rule n3ed_31a4449d86221132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a4449d86221132"
     cluster="n3ed.31a4449d86221132"
     cluster_size="132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['db7a3fdd9024a288b9136f20929ce3b9', 'b766ffe2a5ed4a6f665a04570785e51b', '58837824252ec17d1c9f227f9434ea73']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(286720,1024) == "21cd1f5dd6f252371e6aa6e53f74b815"
}

