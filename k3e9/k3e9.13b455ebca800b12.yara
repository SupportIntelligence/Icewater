import "hash"

rule k3e9_13b455ebca800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13b455ebca800b12"
     cluster="k3e9.13b455ebca800b12"
     cluster_size="10045 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd upatre zbot"
     md5_hashes="['16fd8ade94ca776c9c7724a38addca78', '153aa22f2ce44a8e07364d31e195cd45', '0a20a01e81901869e733f45d6a06b16b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "e817887e94cc763cce2d3cc989d25b5e"
}

