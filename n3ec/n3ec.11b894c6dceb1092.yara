import "hash"

rule n3ec_11b894c6dceb1092
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b894c6dceb1092"
     cluster="n3ec.11b894c6dceb1092"
     cluster_size="5 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="bundler malicious abwx"
     md5_hashes="['31c014fc7f2bbc8898248cbf071879d2', '895d772e38bb2e6d9af36ffcfa81affc', '1760881434d01e1be45b7f288d408074']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(912384,1024) == "5f4ea3de47088c3b89a40a6f0411c75a"
}

