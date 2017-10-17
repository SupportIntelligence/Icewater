import "hash"

rule m3e9_139d965ec6991932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.139d965ec6991932"
     cluster="m3e9.139d965ec6991932"
     cluster_size="1616 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi injector tinba"
     md5_hashes="['1ad5904573112b211527fc871dc55899', '320e95c2acc5050ca7f2a3f2e60e5f2c', '2ca63a12e2a16f4c9beb71c55a97a070']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(126976,1024) == "f636f7c2802b39a5ef95d0a76075e9ba"
}

