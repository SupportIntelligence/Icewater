import "hash"

rule o3e7_12b95e9996c30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.12b95e9996c30932"
     cluster="o3e7.12b95e9996c30932"
     cluster_size="5 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="linkury webtoolbar bdff"
     md5_hashes="['21bfe9de558b4d1faceb93ef69cf427e', '760291f618491d2889e173ea92e90d91', '21bfe9de558b4d1faceb93ef69cf427e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(489949,1025) == "f6f3d57e142b8a3163012efff8585733"
}

