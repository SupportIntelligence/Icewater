import "hash"

rule n3ec_39996a48c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.39996a48c4000b32"
     cluster="n3ec.39996a48c4000b32"
     cluster_size="126 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob sality"
     md5_hashes="['3065da2be84b7008cf0ac098421d8922', '838c046855754876594370c62107a036', '498c2aee7fd9295ea1f482305d88a2ef']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(253952,1024) == "abcdfbc752e04f760df5c2c75a4f47a2"
}

