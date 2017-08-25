import "hash"

rule k3e9_63146ef11daa6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ef11daa6b16"
     cluster="k3e9.63146ef11daa6b16"
     cluster_size="47 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d7bfb54b17c902b1143a59d7f381010d', 'd7bfb54b17c902b1143a59d7f381010d', 'cbdd9ec3b943c01e7766c7bb7e2c46b3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

