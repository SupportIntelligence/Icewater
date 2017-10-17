import "hash"

rule m3e9_73b66c74ea008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73b66c74ea008932"
     cluster="m3e9.73b66c74ea008932"
     cluster_size="55 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['8e633bed68eca87206026cd8f898199d', '2ca426f5d1335286979e99e2e1a3e65c', '7ff3b5a44fb41a2577778456029973c2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(84992,1024) == "967cfe988bc65ab5193f8658032c7ee8"
}

