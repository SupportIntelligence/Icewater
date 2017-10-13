import "hash"

rule m3e7_1c5a6a9dc6220b40
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.1c5a6a9dc6220b40"
     cluster="m3e7.1c5a6a9dc6220b40"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut prepender shodi"
     md5_hashes="['33971219e297776c5f4a3c4e71c536e7', 'a7578fffd1c484583886d5fc02011ce8', 'c705b9f5dd1519b039b951bcff2e14d9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(12288,1024) == "8e58efdccc5d126553629034a59cc997"
}

