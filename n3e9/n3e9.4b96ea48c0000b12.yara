import "hash"

rule n3e9_4b96ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b96ea48c0000b12"
     cluster="n3e9.4b96ea48c0000b12"
     cluster_size="257 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="banker advml banload"
     md5_hashes="['a60a4dd58cf4d1588d0650d888e30d9e', '6cc416887a243933b56e211c8a063485', 'b90086167a8a01dc4c49c4546f3a664a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

