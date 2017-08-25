import "hash"

rule k3e9_51b133169da31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b133169da31132"
     cluster="k3e9.51b133169da31132"
     cluster_size="138 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['2f2544c019a734ff65745b877b026a5e', 'b6e237857e8ac4d60687bb49da119fcf', 'c9e1f35b3cac3b01599db5a50c4fc8a0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,1024) == "5ab8258470efa3d600fcbe17d59a8cd4"
}

