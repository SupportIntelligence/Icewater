import "hash"

rule k3e9_51b1332691a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b1332691a31b32"
     cluster="k3e9.51b1332691a31b32"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a3e779f069ba49df8407509901aa3ca4', 'd5851a65105a56dbd3496a1ee5c2beed', 'd5851a65105a56dbd3496a1ee5c2beed']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,256) == "a770892bd678c7f454784a0c3e9f731c"
}

