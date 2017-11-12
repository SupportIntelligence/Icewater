import "hash"

rule m3e9_5727ea88c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5727ea88c0000932"
     cluster="m3e9.5727ea88c0000932"
     cluster_size="291 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik trojandownloader"
     md5_hashes="['00e52b66e51fc29d3ab2c4fecac49d41', 'aef72c43a39cbf9c2ebac4bd7bde4a8e', 'c767e8d938252ea96613936707436e00']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(59904,1024) == "2d6de7ed7ac8af7983007134cfa26040"
}

