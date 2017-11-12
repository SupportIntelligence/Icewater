import "hash"

rule m3e9_52aca6c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.52aca6c9c8000912"
     cluster="m3e9.52aca6c9c8000912"
     cluster_size="19970 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy tinba backdoor"
     md5_hashes="['02aaad80f93802145782450f250d9bad', '02d9d4194242a01fc47db55dec76a106', '01f73160462df77c20afd7cf5ebe1c4e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(92160,1024) == "888ae8f4fa0ccdb6dc79f6b13f02ca20"
}

