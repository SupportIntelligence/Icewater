import "hash"

rule m3e9_2515669c9ee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2515669c9ee30912"
     cluster="m3e9.2515669c9ee30912"
     cluster_size="352 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran jorik"
     md5_hashes="['bdc8f7053a8db47ae383ab37191d2a28', 'b70d76d99c7a02151107a96711b7173e', '736db7b4753c6a4ef17aaa738f25d463']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(142336,1024) == "e340fc1bae100897d6708a72a46ba4b8"
}

