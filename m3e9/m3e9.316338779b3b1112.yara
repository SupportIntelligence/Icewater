import "hash"

rule m3e9_316338779b3b1112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338779b3b1112"
     cluster="m3e9.316338779b3b1112"
     cluster_size="47 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod viking jadtre"
     md5_hashes="['ba8cc385c3cf08be0d8175b95dc83e16', 'a8d8947419bd74523484a7960c35dba2', '980e7b7ca52ab89eef93a0886d13f3ef']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "85f1932459668fd27cfde94d6b3d6030"
}

