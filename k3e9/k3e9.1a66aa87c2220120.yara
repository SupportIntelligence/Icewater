import "hash"

rule k3e9_1a66aa87c2220120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1a66aa87c2220120"
     cluster="k3e9.1a66aa87c2220120"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob malicious"
     md5_hashes="['c6731df5673bad9e9726e27b82693b64', 'c6731df5673bad9e9726e27b82693b64', 'e200fe561cd93907b9aea1e6bca28e93']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,256) == "77c31aaeddc01a7ca2676a21d225a326"
}

