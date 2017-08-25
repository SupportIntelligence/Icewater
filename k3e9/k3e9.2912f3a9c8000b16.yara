import "hash"

rule k3e9_2912f3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2912f3a9c8000b16"
     cluster="k3e9.2912f3a9c8000b16"
     cluster_size="6 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="backdoor razy injector"
     md5_hashes="['a49c558061d53467158f90b5b044b6cb', 'a303242307f267dfaef70072950f8256', 'af4f13f543dabff0a8f9c2d89ad4bce8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26112,1536) == "b5ed7b029bc65184d8f3a398fb854e6d"
}

