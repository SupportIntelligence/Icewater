import "hash"

rule k3e9_15e149161ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e149161ee311b2"
     cluster="k3e9.15e149161ee311b2"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['2161082dfb42f0655422b54535ce852f', 'b4968f581a15b9a536c584820006e7b2', 'e6b61bae9dc80c1516d94be87102675a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,256) == "78a61b01aadc635b263604b6cef57130"
}

