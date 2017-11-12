import "hash"

rule n3e9_29c64b58d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c64b58d982e313"
     cluster="n3e9.29c64b58d982e313"
     cluster_size="27 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious cuegoe"
     md5_hashes="['b4082f20baa979efa26f5877f01b786a', 'd86e288680f031c272e269625bd5dfab', 'cba12e5cc6f3938834244e1431bec13a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(808448,1076) == "ab5c78a222b72df8502930b7c2966067"
}

