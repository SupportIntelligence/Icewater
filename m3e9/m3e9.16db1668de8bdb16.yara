import "hash"

rule m3e9_16db1668de8bdb16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16db1668de8bdb16"
     cluster="m3e9.16db1668de8bdb16"
     cluster_size="161 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="cerber ransom zbot"
     md5_hashes="['6bd4da7d804f97089c207681f8979dd9', 'c91cbe7e0fd360d387dba62e7cf7ac66', 'd8023b6955a2df277463f90ddde8f152']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27478,1194) == "811274abb03b6b9dc2595ffe838a2055"
}

