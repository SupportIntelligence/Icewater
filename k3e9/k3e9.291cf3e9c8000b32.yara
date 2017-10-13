import "hash"

rule k3e9_291cf3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.291cf3e9c8000b32"
     cluster="k3e9.291cf3e9c8000b32"
     cluster_size="636 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor razy simbot"
     md5_hashes="['9d7496caa4392a4008bd92655f58638f', 'a89ceb55c1f2664350d52b250a83b7ad', 'a869412a7e171538f919c8e1d72ae672']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

