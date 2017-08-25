import "hash"

rule k3e9_139da164cc939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164cc939932"
     cluster="k3e9.139da164cc939932"
     cluster_size="315 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a9ec27c5cfb2b9e6b8f6d21bd7c4d6b7', 'd66e15588e322cfb77f10f9968d38b78', 'e276d30e5c0964c769494164eca459a3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12544,256) == "b563a84f7e0646b6239c507115d8d4a4"
}

