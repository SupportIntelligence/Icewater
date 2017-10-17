import "hash"

rule k3ed_532e6da0c2000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.532e6da0c2000932"
     cluster="k3ed.532e6da0c2000932"
     cluster_size="2069 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy spyware advml"
     md5_hashes="['06c54d5ef7a96dba13d5ae111fb25f65', '1c1b4c5cf4559017175ea079c2a1c5fc', '07b07a22d2a7f6b201c72a5775f9654e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18944,1195) == "4e5be38161d2982ca4fde6a606d1145a"
}

