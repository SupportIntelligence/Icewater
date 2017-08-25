import "hash"

rule k3e9_15e14a161ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e14a161ee311b2"
     cluster="k3e9.15e14a161ee311b2"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b7731a4dc94bf97e12b3212393d2f706', 'ab4dbaf8c78ced2a9dac1abf22fc7b73', 'b7731a4dc94bf97e12b3212393d2f706']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8704,256) == "4cecd67bfd344916fbf73bfee5da9c8f"
}

