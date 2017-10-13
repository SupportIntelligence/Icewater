import "hash"

rule o3e9_43b0fa43c8001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0fa43c8001912"
     cluster="o3e9.43b0fa43c8001912"
     cluster_size="203 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a77d1e00a783ab50c2a72fea134d65d9', 'c552c7653c9c166af50e52c476293017', 'a1ef07ba49e700a5fed042e606665e8a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(988160,1024) == "dedcec7376f784dafad67d41e4def7e5"
}

