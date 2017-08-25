import "hash"

rule o3e7_12b95e99c6000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.12b95e99c6000932"
     cluster="o3e7.12b95e99c6000932"
     cluster_size="37 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="linkury webtoolbar bdff"
     md5_hashes="['2d45b95920683bf39f494bfc2475006d', '7965c64fdf1cb16e30f5deae6f760a79', '3c8a1d349519583bb86485f95942ae1b']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(681814,1081) == "26e31e1d58e00aa3ebe0bf9ec07f2719"
}

