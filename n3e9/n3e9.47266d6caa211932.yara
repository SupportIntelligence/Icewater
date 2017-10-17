import "hash"

rule n3e9_47266d6caa211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.47266d6caa211932"
     cluster="n3e9.47266d6caa211932"
     cluster_size="94 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['99ee78a00bc0b603397a9e9662a5e53b', 'ac436a86f0897bb6604fa75d069dfc29', '659a8a24089b1ac8db869352415f428b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(505856,1024) == "364511aa2d6ff42784f1d1a23a73fae6"
}

