import "hash"

rule m3e9_6b2f17a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f17a9ca000b12"
     cluster="m3e9.6b2f17a9ca000b12"
     cluster_size="13125 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0728cb930b3bc69dbb515bfb0614a519', '06f2790ae66aa76eb9bafde5677d851b', '03184920970b7953232008543fba1326']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(10240,1024) == "d6ce13b328d6c53dfb618f633f2323ac"
}

