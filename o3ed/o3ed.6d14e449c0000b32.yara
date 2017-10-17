import "hash"

rule o3ed_6d14e449c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.6d14e449c0000b32"
     cluster="o3ed.6d14e449c0000b32"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['17608d585fb770e537d7b5a4e2d36e61', '098cdf25149cf445b9dacdb8d09c369f', '17608d585fb770e537d7b5a4e2d36e61']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(362496,1024) == "2c262d66b505baf68ab3851e94a5ba11"
}

