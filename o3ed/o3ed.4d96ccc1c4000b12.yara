import "hash"

rule o3ed_4d96ccc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96ccc1c4000b12"
     cluster="o3ed.4d96ccc1c4000b12"
     cluster_size="1175 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['140aac24be5dd1f3319ea3c85e1be404', '3f14641bc3d28b1922652f0ae3f9fae8', '830066177f9482e1c4cae159553dba49']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1175552,1024) == "46afa767863a1b6f3ddb5d49841540cf"
}

