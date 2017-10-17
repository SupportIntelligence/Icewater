import "hash"

rule n3ed_618616c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.618616c9cc000b32"
     cluster="n3ed.618616c9cc000b32"
     cluster_size="108 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['7c3f95d226380aadefdc8e2695d734b5', 'c2dc0abae2ecfe7cfcdef069df2d31ba', 'd15c3854e3c2b5dcabc7e95041a39fd2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

