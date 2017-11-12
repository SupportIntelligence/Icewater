import "hash"

rule m3e9_231ba1e8c2800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.231ba1e8c2800b12"
     cluster="m3e9.231ba1e8c2800b12"
     cluster_size="229 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['638715b077964b9d99baa689510f4fb0', '2ae6dae2ed7235e4482c600edbd21211', '9639636500159ebf76add5392a1ab5a7']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(56320,1024) == "ef3bfa08a1e4c28928df02bba0a783b9"
}

