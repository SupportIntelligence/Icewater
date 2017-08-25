import "hash"

rule k3e9_51b93126dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93126dda31b32"
     cluster="k3e9.51b93126dda31b32"
     cluster_size="218 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a4527ef7474fb0ad6c6256dc1fbf96d3', 'cc662cf856d221aa63b5990c74d3cbe9', 'da023ad74690b8fdfaa6b77392fcb7f0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,256) == "5d4fa46b1e9f5a523e8809aba451438b"
}

