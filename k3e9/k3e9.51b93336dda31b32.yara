import "hash"

rule k3e9_51b93336dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93336dda31b32"
     cluster="k3e9.51b93336dda31b32"
     cluster_size="253 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['629e2fa9a387a518eb23279ecf19f366', 'aeda3b13b1e342e36a292a579aa88e5d', 'bcf547bd0a5fa283c04c12acf32bf3f4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "0d3081d09f971c3c9d786caf79ac8fb7"
}

