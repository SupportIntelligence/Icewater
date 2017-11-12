import "hash"

rule o3e9_61368808890d6b92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.61368808890d6b92"
     cluster="o3e9.61368808890d6b92"
     cluster_size="7383 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="optimizerpro generickd speedingupmypc"
     md5_hashes="['178007c63f1757e53afab5731f180fd8', '0dc3ad6c2ec1b55a34fcbd7eec514268', '0226a12296861f60f420dc94a0a52260']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3633664,1024) == "ad9f1a38ddffc6e3915831ed25ef4b27"
}

