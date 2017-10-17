import "hash"

rule m3e9_411e3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411e3ac1cc000b12"
     cluster="m3e9.411e3ac1cc000b12"
     cluster_size="230 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['de417aa4a356fd3f1dd007834d590513', 'd537d587c91e857fd0c908138c6a044a', 'c2321d0c31f8de8f40a0905745eb54f3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "38345c2f0e0fb848e12408e6736482bc"
}

