import "hash"

rule k3e9_65d852ef9e630912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.65d852ef9e630912"
     cluster="k3e9.65d852ef9e630912"
     cluster_size="770 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ibryte adload ejtxwd"
     md5_hashes="['1389d8229fd8ec7da8390c98e8ad49c3', '3521442c88bebd7df35e80fa345aa3b6', '5d06daffa596c1fd9a98389b2bb5075e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(32256,1536) == "2aa587c909999ca52be17d0f1ffbd186"
}

