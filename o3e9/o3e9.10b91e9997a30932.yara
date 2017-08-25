import "hash"

rule o3e9_10b91e9997a30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.10b91e9997a30932"
     cluster="o3e9.10b91e9997a30932"
     cluster_size="5 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="linkury webtoolbar bdff"
     md5_hashes="['6f7481b0b1c4e204633ce3b4839c5597', '4f11f14cd2e818191182c576169ce682', '92c5a00491875599a34fde31505688d9']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(489949,1025) == "f6f3d57e142b8a3163012efff8585733"
}

