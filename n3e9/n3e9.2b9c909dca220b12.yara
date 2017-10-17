import "hash"

rule n3e9_2b9c909dca220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b9c909dca220b12"
     cluster="n3e9.2b9c909dca220b12"
     cluster_size="1090 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="incredimail webtoolbar hfsadware"
     md5_hashes="['335ce9045930370e8c9e0254fd79d97b', '0f626630fae6293f985272a00acf957e', '335ce9045930370e8c9e0254fd79d97b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(28040,1039) == "31bb432581fc27c302cbcfbd494d121e"
}

