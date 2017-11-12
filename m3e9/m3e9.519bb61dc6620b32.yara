import "hash"

rule m3e9_519bb61dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.519bb61dc6620b32"
     cluster="m3e9.519bb61dc6620b32"
     cluster_size="190 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['93d8ae9c4f97d7fd193385aa1885fff6', '98a86c5cc8092d7844d32383ce9099e4', 'ccfa8a51e24a2db61e1b066b7a1d935f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64000,1024) == "3a2b8b8e8c5ba0975f11e47f5b4896fd"
}

