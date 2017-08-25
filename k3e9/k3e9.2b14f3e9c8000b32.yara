import "hash"

rule k3e9_2b14f3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b14f3e9c8000b32"
     cluster="k3e9.2b14f3e9c8000b32"
     cluster_size="136 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['07dbec89fb96a55d91c6279ed6f227e0', 'd3b5be4053bda26050d31964e35d646a', 'f217a5700a1b3934c8e075acc53e80e7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

