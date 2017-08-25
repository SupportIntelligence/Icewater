import "hash"

rule o3e7_12b96a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.12b96a48c0000932"
     cluster="o3e7.12b96a48c0000932"
     cluster_size="6 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="linkury webtoolbar bdff"
     md5_hashes="['0c5f0d64903d8d9712073faea4d39bf1', '159dbd2f648139eb886b1aefb4aee587', '0c5f0d64903d8d9712073faea4d39bf1']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(681814,1081) == "26e31e1d58e00aa3ebe0bf9ec07f2719"
}

