import "hash"

rule k3e9_139da164c9c39932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164c9c39932"
     cluster="k3e9.139da164c9c39932"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e7bb54255bad767b94373f270ee21329', 'bb19d13554209e03ed08d3b303cd3409', 'c9182ac8929c3c7cf9b6f2996aed5023']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1024) == "19f46802217b7e74f63dc75432304b31"
}

