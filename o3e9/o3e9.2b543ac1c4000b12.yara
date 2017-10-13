import "hash"

rule o3e9_2b543ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b543ac1c4000b12"
     cluster="o3e9.2b543ac1c4000b12"
     cluster_size="14 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="malicious kryptik attribute"
     md5_hashes="['ccaeb70ce2345f1c97c69bf5586c0bae', 'bccfdabe4b1d505a293b7c6d10f64b56', 'fcf7544546ae8305841dcf2a1962e338']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1589248,1024) == "61f18f67064a449566f3db098734987b"
}

