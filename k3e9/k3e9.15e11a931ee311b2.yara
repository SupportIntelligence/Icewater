import "hash"

rule k3e9_15e11a931ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e11a931ee311b2"
     cluster="k3e9.15e11a931ee311b2"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c51600b170bee175fe6dc79de1e5a888', 'ddddb3d8e9c64d140cd6d7cf813312fd', 'c643a287487d408d14f39a7f55f48037']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8704,256) == "4cecd67bfd344916fbf73bfee5da9c8f"
}

