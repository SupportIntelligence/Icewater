import "hash"

rule n3e9_1ba57ec1c4000916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba57ec1c4000916"
     cluster="n3e9.1ba57ec1c4000916"
     cluster_size="1801 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="pykspa vilsel pykse"
     md5_hashes="['5385657adee0004cac50a775ffd37760', '5c2b35868566e1ba4301c5de37577b1f', '14f90a0a4ca1520c635d0bf6ac24a4ef']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(184320,1024) == "4a7eda87e55f7b49d27eddf547ee733b"
}

