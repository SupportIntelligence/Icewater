import "hash"

rule n3ec_11b894c6d9eb1092
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b894c6d9eb1092"
     cluster="n3ec.11b894c6d9eb1092"
     cluster_size="14 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="bundler malicious abwx"
     md5_hashes="['6650bea8f7586d19b22c5aa5a711ce6f', '51e35ab824cabb280e180953da967e48', '5c7c9e3ed78098c98d1917946ee99315']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(912384,1024) == "5f4ea3de47088c3b89a40a6f0411c75a"
}

