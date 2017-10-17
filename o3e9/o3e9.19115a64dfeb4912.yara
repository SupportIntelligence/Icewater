import "hash"

rule o3e9_19115a64dfeb4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19115a64dfeb4912"
     cluster="o3e9.19115a64dfeb4912"
     cluster_size="1561 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="blackv noobyprotect malicious"
     md5_hashes="['4498cda45e5b6085fb2a78461671882b', '3a17ef0c0a37d03f904be21d89f163d1', '234c33ae261b45f32400d4634779fec7']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1354795,1024) == "59ddd9af97e034f27a8d1fbe371ca4f7"
}

