import "hash"

rule k3e9_699446a9813f9b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.699446a9813f9b32"
     cluster="k3e9.699446a9813f9b32"
     cluster_size="8672 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jqap small zbot"
     md5_hashes="['1c15dac32ece01f34c34822f88a78e09', '0749eab10f7719106b0dd244850261b4', '0f16d9e93b82975b52b9d36d453d3966']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "46ed381652e45b6d895092742666b2db"
}

