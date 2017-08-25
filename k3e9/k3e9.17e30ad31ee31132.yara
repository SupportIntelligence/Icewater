import "hash"

rule k3e9_17e30ad31ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30ad31ee31132"
     cluster="k3e9.17e30ad31ee31132"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d5188caf144d90951b6b3ca96d325150', 'ab88110a6dc9538ce7613dc080db7527', 'ab88110a6dc9538ce7613dc080db7527']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,256) == "78a61b01aadc635b263604b6cef57130"
}

