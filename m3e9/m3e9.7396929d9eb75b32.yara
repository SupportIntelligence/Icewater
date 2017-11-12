import "hash"

rule m3e9_7396929d9eb75b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7396929d9eb75b32"
     cluster="m3e9.7396929d9eb75b32"
     cluster_size="22692 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="murofet zbot small"
     md5_hashes="['0688721f89acd3ad8d1ee99063ac51cd', '000a9324d40b9e3aa466a8b22c28c136', '00fb5f1c18022450cb61d4cfd7fa6941']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(19456,1024) == "1bc63b563418ac0acb5d3ad2ea595cae"
}

