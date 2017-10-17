import "hash"

rule k3e9_3b1cf3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b1cf3a9c8000b16"
     cluster="k3e9.3b1cf3a9c8000b16"
     cluster_size="77 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy backdoor injector"
     md5_hashes="['ac5c14f09b16be1e0731584b0f9d53c0', '0c93191a5e603f507fe9ed014049cba8', 'ba6613035dcc33a548b591ac8bdf4bc3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

