import "hash"

rule k3e9_05a85ed1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.05a85ed1cc000932"
     cluster="k3e9.05a85ed1cc000932"
     cluster_size="1572 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd bublik upatre"
     md5_hashes="['08d1190c35b1f27be40d3e6bde718555', '63371aa676a03d6e93ac8a4de5811a97', '866e2fbdce020eecdcc5105d89687788']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3176,1075) == "40d6ef3e79918998058fc752641877d5"
}

