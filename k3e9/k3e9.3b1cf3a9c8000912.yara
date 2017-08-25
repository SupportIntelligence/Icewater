import "hash"

rule k3e9_3b1cf3a9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b1cf3a9c8000912"
     cluster="k3e9.3b1cf3a9c8000912"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="razy backdoor injector"
     md5_hashes="['cb3cc9dea5e87627fa685052045f8200', 'aedbbcc56650c6e9f82a19fd0d106f2d', 'aedbbcc56650c6e9f82a19fd0d106f2d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

