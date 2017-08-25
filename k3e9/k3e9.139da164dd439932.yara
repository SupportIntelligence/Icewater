import "hash"

rule k3e9_139da164dd439932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164dd439932"
     cluster="k3e9.139da164dd439932"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c88573d291e404092c87293c47d87fa0', 'd6f8288f3298f5b27edecba197ecf1d5', 'bf46562b78c71a407f55096a3411c282']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16896,256) == "8289f17bd508c11dbe7ba0413e7e3252"
}

