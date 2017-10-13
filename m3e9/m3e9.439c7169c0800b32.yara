import "hash"

rule m3e9_439c7169c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.439c7169c0800b32"
     cluster="m3e9.439c7169c0800b32"
     cluster_size="1437 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['035d09efee34e3549ec90de161c8efad', '0b8850e0aa4b8c3311c8f1cbe17a8a8e', '02126edc5e5533ad8057402731876987']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "ea3c338d29e9244b4487eec622d3ed34"
}

