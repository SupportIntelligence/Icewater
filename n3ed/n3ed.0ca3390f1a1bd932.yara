import "hash"

rule n3ed_0ca3390f1a1bd932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a1bd932"
     cluster="n3ed.0ca3390f1a1bd932"
     cluster_size="1145 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['170f3695cd2c1cd740098137cf145f8a', '3375550a87e9abae04ad83bb3412ee81', '2026c4f5e0c60cd82b2b188bcfd25313']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(641536,1536) == "b83d54d068c17ef67e7b9236dbb3528c"
}

