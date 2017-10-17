import "hash"

rule n3e9_1114e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1114e448c0000b32"
     cluster="n3e9.1114e448c0000b32"
     cluster_size="75 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="expiro cfeb hlux"
     md5_hashes="['a25e1cfcf677f8486988b71492ffad64', 'be68f28703d471fe4ea96bd02ce927e2', 'bd94c742aa3d75668e4525abb160b92f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(280576,1024) == "2cd08b4eeea1bb1ba128f2e1a7234d91"
}

