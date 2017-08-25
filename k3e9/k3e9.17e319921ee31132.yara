import "hash"

rule k3e9_17e319921ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e319921ee31132"
     cluster="k3e9.17e319921ee31132"
     cluster_size="98 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e6e8b4c9f76b230a807963bedd5ee252', 'd09218552b7d959502ced2fe016bc6fe', '4db26e6ad4e5b3452aa34e9b15a19f66']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "2d0a794179422cbb47ac4f30a07f9908"
}

