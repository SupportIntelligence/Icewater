import "hash"

rule m3e9_636684679d994d16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.636684679d994d16"
     cluster="m3e9.636684679d994d16"
     cluster_size="103 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob classic"
     md5_hashes="['c2ce3c40ed11bfd6ae5ff376b52aa252', 'b5a7cdd18f5ec1b515cde90679322124', '279b01f5b8bf5b68b3704986abbd1875']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(189440,1024) == "64a6f9fa137f9145623faf227205f34c"
}

