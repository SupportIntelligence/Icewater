import "hash"

rule k3e9_51b1312699a31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b1312699a31b32"
     cluster="k3e9.51b1312699a31b32"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['af052cef5c47e76a5bbb67fca7ef4711', 'bd259316c2db6b758368ea073232d171', 'bd259316c2db6b758368ea073232d171']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,256) == "286a6db30376a984ee1706d41700b1f3"
}

