import "hash"

rule n3e9_05b529b9c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b529b9c2210b32"
     cluster="n3e9.05b529b9c2210b32"
     cluster_size="4682 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="renamer delf grenam"
     md5_hashes="['280ff9168039d336dfe8e391c687dd23', '307d4d396d91203a1b80f40f2472a787', '30232d193e7fbd7f608337448375bfff']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(463929,1081) == "87a736d096dd8f6c5aae9a67e116e67e"
}

