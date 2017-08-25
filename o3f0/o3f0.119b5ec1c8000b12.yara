import "hash"

rule o3f0_119b5ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.119b5ec1c8000b12"
     cluster="o3f0.119b5ec1c8000b12"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious fner icloader"
     md5_hashes="['591cf459dfde14f8266e5e8412515ebf', 'd277d0e56612c6ff904a1b99d9f145c1', '87810440cf2e238d2d8d749d6ca21528']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1272832,1024) == "1d2fdb98df1a68ea5c90cfccb6318eb0"
}

