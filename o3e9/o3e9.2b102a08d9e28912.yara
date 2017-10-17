import "hash"

rule o3e9_2b102a08d9e28912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b102a08d9e28912"
     cluster="o3e9.2b102a08d9e28912"
     cluster_size="2732 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="strictor noobyprotect advml"
     md5_hashes="['32f16957abff5a5f84334eb3367b731f', '2afcaa5a8f622e8e60a4be0e34516a8c', '0c9e3f993caa50993a0416e3b9f6bb54']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3104768,1024) == "b2044e2bd6dda24bdef1656ad5cf58c8"
}

