import "hash"

rule m3e9_16c339374922f914
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c339374922f914"
     cluster="m3e9.16c339374922f914"
     cluster_size="103 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="shipup zbot faqw"
     md5_hashes="['c0027498c4e7fee2c9eceac88661bb7f', 'a0a8ced145186bba6c6a694a942abd88', '3bf3e2cf46662df1bbeee5ee9e288c0e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(1024,1048) == "75483afc43cb1d8842187323a047d6f6"
}

