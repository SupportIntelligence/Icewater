import "hash"

rule p3e9_119d5ec1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.119d5ec1cc000b12"
     cluster="p3e9.119d5ec1cc000b12"
     cluster_size="614 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ircbot backdoor dorv"
     md5_hashes="['b20e269f11e6479db9f8ecc7fce483ce', '90111183482fe0d9388496cd4efadbb6', 'b14a5682043466e6d817d1d3c8712830']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(79788,1030) == "d3e5be795e3c1744053621665c7c209d"
}

