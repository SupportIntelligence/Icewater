import "hash"

rule m3ec_199924d4dee30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.199924d4dee30932"
     cluster="m3ec.199924d4dee30932"
     cluster_size="5210 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hackkms archsms hacktool"
     md5_hashes="['277d4a9e3d3c66d676b4cee7b8b3a1f3', '0e91f792b68b609fac3a67ee02633709', '0a72f313448e4f1107c68e6a317e5870']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123904,1024) == "341199b87b62f9400e85d6910500c9cd"
}

