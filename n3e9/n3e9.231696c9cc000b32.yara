import "hash"

rule n3e9_231696c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.231696c9cc000b32"
     cluster="n3e9.231696c9cc000b32"
     cluster_size="14792 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="kazy injector backdoor"
     md5_hashes="['037ea854c0534631f67256f878810e16', '07065b7fb1ded4fff33006397f01ff5e', '03e63dbd3ba99af6db787f6bc9ee99f5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(125952,1024) == "bb974527ec5e0c569d4929e05303d26c"
}

