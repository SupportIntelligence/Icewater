import "hash"

rule k3e9_3916f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3916f3a9c8000b32"
     cluster="k3e9.3916f3a9c8000b32"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['a1a0375b2d3309b8156210bf79dcbafb', 'a2349b150c4922cae9f0155e3faa59f5', 'a1a0375b2d3309b8156210bf79dcbafb']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

