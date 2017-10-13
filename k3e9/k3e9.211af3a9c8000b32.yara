import "hash"

rule k3e9_211af3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211af3a9c8000b32"
     cluster="k3e9.211af3a9c8000b32"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['09f1970422e9cec548629466caa8668d', 'a3ffe556292951938f699d62f1f64e4a', 'b7c6cf1c882e4167224b9bb0b3b43ade']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

