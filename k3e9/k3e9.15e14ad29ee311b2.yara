import "hash"

rule k3e9_15e14ad29ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e14ad29ee311b2"
     cluster="k3e9.15e14ad29ee311b2"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c0b968a3d425bd1a3bdc60a895ba78f3', 'b66d8bbd4789d5494af92407b6d7c8ba', 'cf910dccf9cd55ea9755d7fc1bcb4444']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8704,256) == "4cecd67bfd344916fbf73bfee5da9c8f"
}

