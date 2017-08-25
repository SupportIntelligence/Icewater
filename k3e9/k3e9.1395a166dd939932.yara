import "hash"

rule k3e9_1395a166dd939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a166dd939932"
     cluster="k3e9.1395a166dd939932"
     cluster_size="139 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['acc36e530de7e8ff78b8a5c8a060f9ba', '3e0e6b5b6623bf09462f8d94812c0640', 'e69ffa1c8c37f2730f1ce35f1595db35']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

