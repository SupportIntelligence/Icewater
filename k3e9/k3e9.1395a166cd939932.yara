import "hash"

rule k3e9_1395a166cd939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a166cd939932"
     cluster="k3e9.1395a166cd939932"
     cluster_size="87 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['6f9f0aa445c153430abbc31e0bc46207', 'be9ac083e0073deff029bab29a38c0d2', 'aebf340b9a16c5052d6df288cfba0c8c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

