import "hash"

rule k3e9_51b13306dfa31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b13306dfa31b32"
     cluster="k3e9.51b13306dfa31b32"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a4255019259e6a18d3f63377ea07ca2d', '18648ae844273f3b2379c8a11dd00f00', 'bac0d4a7dcdac8115d10f2a4fe323f50']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "b64b84b038538c4ad2cc9e52262cbc46"
}

