import "hash"

rule k3e9_2114f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2114f3a9c8000b12"
     cluster="k3e9.2114f3a9c8000b12"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['d7abe0ffa2698c17a58e791841f3f6f4', '7a5b8e6a3151b66399d3120700e006f0', '6c06bb050a50d49d439297efa149f00f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

