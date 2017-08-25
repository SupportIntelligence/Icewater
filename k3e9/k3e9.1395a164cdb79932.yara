import "hash"

rule k3e9_1395a164cdb79932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a164cdb79932"
     cluster="k3e9.1395a164cdb79932"
     cluster_size="20 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d112c030c95faa10a3515ad1d4a5e5e7', 'a18ffab654d678a75cd3a9ab270d9f3f', 'd112c030c95faa10a3515ad1d4a5e5e7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "10942184959ee54e3c7f95e54fa08bca"
}

