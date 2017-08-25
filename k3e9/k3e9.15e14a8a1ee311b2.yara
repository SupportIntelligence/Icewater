import "hash"

rule k3e9_15e14a8a1ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e14a8a1ee311b2"
     cluster="k3e9.15e14a8a1ee311b2"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a81d23f4883f427fba8290e0ea0bd415', 'a81d23f4883f427fba8290e0ea0bd415', '69fb786d19fccb0e01f8f78d89d5d09f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8960,256) == "5201da99e9d8cde0d527b97921e342e9"
}

