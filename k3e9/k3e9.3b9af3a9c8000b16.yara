import "hash"

rule k3e9_3b9af3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b9af3a9c8000b16"
     cluster="k3e9.3b9af3a9c8000b16"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['b56159b52492af77393f6bd404659926', '3b76d64411f99f6dd35875f8c2b620da', 'b56159b52492af77393f6bd404659926']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

