import "hash"

rule m3e9_519bb61dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.519bb61dc6220b32"
     cluster="m3e9.519bb61dc6220b32"
     cluster_size="376 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dab84fd6391c9946321f313c2b281d04', 'ceb4719b2360bf42d0f670da5c936b5e', 'ae1ee820794d9f0290407916701f5f48']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64000,1024) == "3a2b8b8e8c5ba0975f11e47f5b4896fd"
}

