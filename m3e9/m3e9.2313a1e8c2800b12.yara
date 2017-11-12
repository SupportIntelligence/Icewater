import "hash"

rule m3e9_2313a1e8c2800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2313a1e8c2800b12"
     cluster="m3e9.2313a1e8c2800b12"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b2ef8129d2a83b771e5dd613cecac41a', '9f0dc2b2912ac976ed5f62ac8acf51d5', '1756236a0c12573ac3281bfc63520447']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(56320,1024) == "ef3bfa08a1e4c28928df02bba0a783b9"
}

