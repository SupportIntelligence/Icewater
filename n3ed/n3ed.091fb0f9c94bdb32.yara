import "hash"

rule n3ed_091fb0f9c94bdb32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c94bdb32"
     cluster="n3ed.091fb0f9c94bdb32"
     cluster_size="1452 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['05e5f74e31606d861f62081fee35326d', '790d8f49e4c84f68e2ed7524ee0c6590', '5de73a2c455941fbe935e68071300154']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

