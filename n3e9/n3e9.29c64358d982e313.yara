import "hash"

rule n3e9_29c64358d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c64358d982e313"
     cluster="n3e9.29c64358d982e313"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious cuegoe"
     md5_hashes="['0fd6aa7d01d3798e2123bb16db0f0853', 'b4720f6ef97b90bfdf5b70dcc6e59fa7', 'c7a31fb7081a97f80b40cc027c773331']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(808448,1076) == "ab5c78a222b72df8502930b7c2966067"
}

