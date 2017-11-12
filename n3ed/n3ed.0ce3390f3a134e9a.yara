import "hash"

rule n3ed_0ce3390f3a134e9a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a134e9a"
     cluster="n3ed.0ce3390f3a134e9a"
     cluster_size="304 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c0815b250e4ed658506abbd3ef0ba872', '41758dae87726869d2f2dd2520d3eb79', 'e8c9cea5f5c123feec474f9e4c2479ed']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(641536,1536) == "b83d54d068c17ef67e7b9236dbb3528c"
}

