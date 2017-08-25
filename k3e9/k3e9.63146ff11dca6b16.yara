import "hash"

rule k3e9_63146ff11dca6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11dca6b16"
     cluster="k3e9.63146ff11dca6b16"
     cluster_size="134 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b0ba3f5237c1bff89e394980b2f6ee3c', '220206e25be5eaff0c3e36f7f00a4ebb', 'fabcb123a577d7df4fe73fdaacdc245f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

