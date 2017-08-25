import "hash"

rule n3e9_05b529b9ca210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b529b9ca210b32"
     cluster="n3e9.05b529b9ca210b32"
     cluster_size="1992 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="renamer delf grenam"
     md5_hashes="['246e046fb4583b339390fa79fdc3e406', '24faef2b6d1787795567fb3ba30e4e10', '0ca1ed6c0469c2657feca32284a98100']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(463929,1081) == "87a736d096dd8f6c5aae9a67e116e67e"
}

