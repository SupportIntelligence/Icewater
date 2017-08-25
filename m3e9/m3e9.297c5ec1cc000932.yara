import "hash"

rule m3e9_297c5ec1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.297c5ec1cc000932"
     cluster="m3e9.297c5ec1cc000932"
     cluster_size="16938 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['035bb30333efe8e84b6a8c2b5273e2d9', '01a46739b189cb3914aed5d341472f87', '05292fcbffb01f921bb67e59b87cdb4d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(2112,1088) == "cb374ad2f45c016f040cef6ce6eddd16"
}

