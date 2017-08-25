import "hash"

rule n3ec_11b896d6dceb1092
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b896d6dceb1092"
     cluster="n3ec.11b896d6dceb1092"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="bundler malicious abwx"
     md5_hashes="['07dee4cfbc97a66f87cd98f762cbd5b8', '07dee4cfbc97a66f87cd98f762cbd5b8', '07dee4cfbc97a66f87cd98f762cbd5b8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(912384,1024) == "5f4ea3de47088c3b89a40a6f0411c75a"
}

