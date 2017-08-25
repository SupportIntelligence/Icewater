import "hash"

rule n3ed_31a4469986621132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a4469986621132"
     cluster="n3ed.31a4469986621132"
     cluster_size="678 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['3d4981a0909fdbc589a01823b9ab606f', '0f39357163c30dc75e52b09dc0c1b500', 'a27b537ead3bdc9b69ccd8eb24ab8723']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(286720,1024) == "21cd1f5dd6f252371e6aa6e53f74b815"
}

