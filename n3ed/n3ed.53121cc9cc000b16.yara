import "hash"

rule n3ed_53121cc9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53121cc9cc000b16"
     cluster="n3ed.53121cc9cc000b16"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c626cca94c21e45068612dd736e09aa9', 'd8729c053455fd58971de43a1a963513', 'c7add5cff437575ebe853c355590f3e6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

