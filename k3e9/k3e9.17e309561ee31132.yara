import "hash"

rule k3e9_17e309561ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e309561ee31132"
     cluster="k3e9.17e309561ee31132"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a2b576a38b6d6d19b54ae2ee2f8214f3', 'e63500bf6f66fc87dea3d48bfdd8fea5', 'c41d7bc63dd2b58d6adc0e8291f10f0d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "2f71af6522927f93cb15efa00c89d5db"
}

