import "hash"

rule k3e9_15e11c921ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e11c921ee31132"
     cluster="k3e9.15e11c921ee31132"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c2a2dd48395383b0946fe20adc312b43', 'b11db85f7bb95a9e6ced7e401eee7262', 'cad23e51a1646a708cb220716576622c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19200,256) == "3b15958506c859264d98a47823d86ece"
}

