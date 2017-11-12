import "hash"

rule n3e9_11599299c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.11599299c9000b16"
     cluster="n3e9.11599299c9000b16"
     cluster_size="1576 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0df67a5cf235b04019e38ea8beef820e', '6ca3fd0431305f663594f0adb346e1ad', '6b2d0f4fbfa5f8dc5cfa09c7bedff2c7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(195584,1152) == "a65d524274c61b52c50b4f8a9faef5d7"
}

