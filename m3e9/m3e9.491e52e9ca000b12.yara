import "hash"

rule m3e9_491e52e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.491e52e9ca000b12"
     cluster="m3e9.491e52e9ca000b12"
     cluster_size="340 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus symmi wbna"
     md5_hashes="['2a8f4e4cedd750e02fa2fda4159f9262', 'd12b010d3d42c05bdd74a833ee9549fd', '60dcfb48dc2796e01845ce8e4c344ee0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(39936,1024) == "20b11b5422b9eb76558c4a528b2cb665"
}

