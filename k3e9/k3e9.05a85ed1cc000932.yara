import "hash"

rule k3e9_05a85ed1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05a85ed1cc000932"
     cluster="k3e9.05a85ed1cc000932"
     cluster_size="624 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="generickd bublik upatre"
     md5_hashes="['77d6b22755a45b5e584aa2d6260663f1', 'b3f936ccdcff68a51af73086739e8fae', '4e2f07675dde39f091908e08ba021af2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3176,1075) == "40d6ef3e79918998058fc752641877d5"
}

