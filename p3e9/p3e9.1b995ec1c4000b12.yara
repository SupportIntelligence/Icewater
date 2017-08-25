import "hash"

rule p3e9_1b995ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.1b995ec1c4000b12"
     cluster="p3e9.1b995ec1c4000b12"
     cluster_size="1287 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="agaeq badfile heuristic"
     md5_hashes="['33ae5a25006281f7b75a94edce5c9171', '31c81dbe1a695775b4b833d8bd2760bf', '0a39c17caf89c049476d6f663b9fccc4']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(1688576,1024) == "c2ad34e711465616f04b352fc0604801"
}

