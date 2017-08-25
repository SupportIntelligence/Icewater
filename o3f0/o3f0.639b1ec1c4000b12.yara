import "hash"

rule o3f0_639b1ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.639b1ec1c4000b12"
     cluster="o3f0.639b1ec1c4000b12"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious heuristic icloader"
     md5_hashes="['41e06c52d2a4180f98a910be9c6f1f9c', 'b366f0aab8dd222ead3d85af2998375e', '41e06c52d2a4180f98a910be9c6f1f9c']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1268736,1024) == "1d2fdb98df1a68ea5c90cfccb6318eb0"
}

