import "hash"

rule o3f0_419b1ec1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.419b1ec1c8000b32"
     cluster="o3f0.419b1ec1c8000b32"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious attribute classic"
     md5_hashes="['4fceedcb9361dd827d97817f7dcbf448', '177eaf3b02e3de28e410dadbf808287c', '5c7543be190e634157a87c5054cb25a8']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1245184,1024) == "9855a4a929abdfd1c8aadda0d4e74fe1"
}

