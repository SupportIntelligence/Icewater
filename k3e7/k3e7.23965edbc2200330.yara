import "hash"

rule k3e7_23965edbc2200330
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.23965edbc2200330"
     cluster="k3e7.23965edbc2200330"
     cluster_size="80 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy linkury toolbar"
     md5_hashes="['c8726eaf690ffe76aadf22dfde5b01d7', '42564a49d002a924272c1646c906ea78', '6345136f44ba2fc195e877e396ad4a0b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(31232,263) == "063fae6574c0e44a398e2c1b3a7c0064"
}

