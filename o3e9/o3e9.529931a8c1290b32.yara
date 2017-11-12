import "hash"

rule o3e9_529931a8c1290b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.529931a8c1290b32"
     cluster="o3e9.529931a8c1290b32"
     cluster_size="75 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury bdff"
     md5_hashes="['c8dd6a1e5ca3947bedb16919f4fecc2d', 'bfec467cd1e4187a801345db61038af4', '03beca016258649dfaee0cb213ef3ccb']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2721120,1044) == "7ed2738526c85bdece26d69829235672"
}

