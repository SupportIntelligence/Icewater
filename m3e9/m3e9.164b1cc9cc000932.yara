import "hash"

rule m3e9_164b1cc9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.164b1cc9cc000932"
     cluster="m3e9.164b1cc9cc000932"
     cluster_size="336 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bb3c3d36a6f3976ba3a39a6f4f8f87a4', '35ab10d80d443d3ec19930a589974c3d', '9602cff0c82032ec4e827f9d5eb7f8f8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(29184,1536) == "cf692e5fbaebba02c2ad95f4ba0e60be"
}

