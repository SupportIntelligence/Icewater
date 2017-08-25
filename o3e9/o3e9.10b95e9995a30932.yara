import "hash"

rule o3e9_10b95e9995a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.10b95e9995a30932"
     cluster="o3e9.10b95e9995a30932"
     cluster_size="331 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="linkury webtoolbar bdff"
     md5_hashes="['1c69ba27a365200bbbdb4efc4909f5ae', 'bd247d7d2792abf2d1d7c9960a970fd8', 'e63e96dcd9708fa075ab22c60d67d69f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(681814,1081) == "26e31e1d58e00aa3ebe0bf9ec07f2719"
}

