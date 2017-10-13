import "hash"

rule k3e9_191df3e9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.191df3e9c8000b16"
     cluster="k3e9.191df3e9c8000b16"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['bfb5f1ea465b356840a5ef9c4cb2561c', 'bfb5f1ea465b356840a5ef9c4cb2561c', 'bfb5f1ea465b356840a5ef9c4cb2561c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(25600,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

