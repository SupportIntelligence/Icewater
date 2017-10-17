import "hash"

rule o3e9_381dea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.381dea48c0000b12"
     cluster="o3e9.381dea48c0000b12"
     cluster_size="208 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor banbra banker"
     md5_hashes="['730b5958b546a479c82f7f384aa6bd96', '0d535161902724c8762236badade52ff', '7ff88c45462288391e45729f6dec23d2']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(706048,1024) == "976cc86ce681944f179ca71a9bf7412a"
}

