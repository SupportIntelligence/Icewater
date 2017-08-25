import "hash"

rule n3ed_3b996a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.3b996a49c0000932"
     cluster="n3ed.3b996a49c0000932"
     cluster_size="2057 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="browsefox yotoon bplug"
     md5_hashes="['132e73a6c24823619a60c8fa54ccf810', '1a217984fd1e1f588cc1adee9095b8d7', '0b303d33f2f74b1f3e71393a70b28bf2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(258048,1024) == "ca9548a4b79660b79996c0061c9297fa"
}

