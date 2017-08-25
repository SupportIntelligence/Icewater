import "hash"

rule k3e9_139ce164dd9b9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ce164dd9b9932"
     cluster="k3e9.139ce164dd9b9932"
     cluster_size="15 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e6eac00c8a8ce0dbbd7e2e1486f807f5', 'e30d564e5a8ac1396282d15dd4aeebd5', 'b0b01eca82535c9a6e6db152910dc1fe']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

