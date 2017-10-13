import "hash"

rule o3ed_4d96dcc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96dcc1c4000b12"
     cluster="o3ed.4d96dcc1c4000b12"
     cluster_size="344 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c9a7eee23228efcb409947f7bb28f948', 'b39b8e13b7f6a67ff9ce64fb57f0a108', 'd32039321987d1048e2e7a0e84770962']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1090560,1024) == "911c2f8501f8e0e5dee0dd35e6ef1f93"
}

