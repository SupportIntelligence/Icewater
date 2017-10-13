import "hash"

rule p3e9_2ccb07c8c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.2ccb07c8c0000b12"
     cluster="p3e9.2ccb07c8c0000b12"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="symmi archsms hoax"
     md5_hashes="['e733a8623a04f147ab3283775e4d84dd', 'be7041a471bd659534588947da444212', '7cbb9a9d367d27499ea86e241bc4d1fa']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4897792,1024) == "8483a6a53f5857bde85fb8e082a257a8"
}

