import "hash"

rule k3e9_2916f3e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2916f3e9c8000b32"
     cluster="k3e9.2916f3e9c8000b32"
     cluster_size="459 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['8bce780c9df4aa03bd13f8c19cbbd35a', '9c0e8107ebef732ea52dc129d7444ad8', 'b14fbaf3ec2bbb297bfba0c109fdb474']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

