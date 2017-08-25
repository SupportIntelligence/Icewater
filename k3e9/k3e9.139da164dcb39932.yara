import "hash"

rule k3e9_139da164dcb39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164dcb39932"
     cluster="k3e9.139da164dcb39932"
     cluster_size="99 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0ec37edea79609b15f0389e61c95fc25', 'be9db9c5568dd1b39070d83b12a625c5', 'c525ee7c3a9f37a3ae3a4d238f7dc8b6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

