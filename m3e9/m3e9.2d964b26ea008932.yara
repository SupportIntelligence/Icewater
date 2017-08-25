import "hash"

rule m3e9_2d964b26ea008932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2d964b26ea008932"
     cluster="m3e9.2d964b26ea008932"
     cluster_size="110 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d0d73e7ce7e4b0d163cd423f863051cf', 'ab1a2e211d2fb318743f8190d1f548ba', '4bc98c05282dd68ed0a8fba9802c3001']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d0d038130aeb82cf87189ddf5ec47c53"
}

