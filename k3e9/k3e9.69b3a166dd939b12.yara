import "hash"

rule k3e9_69b3a166dd939b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69b3a166dd939b12"
     cluster="k3e9.69b3a166dd939b12"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['475974f261cbc7891c6f462a68a4ff0c', '6e9d345e4572bd5a5239d424bdba21e9', '475974f261cbc7891c6f462a68a4ff0c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29696,1024) == "e80a176189c7256ffe184b172e0d7cc5"
}

