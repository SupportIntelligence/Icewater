import "hash"

rule m3e9_16c1b9494a9664f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.16c1b9494a9664f2"
     cluster="m3e9.16c1b9494a9664f2"
     cluster_size="147 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup razy zbot"
     md5_hashes="['66c29d2e70009883a83a60de2bcf9c3c', 'd0ebf0f54f5f61a84647ecb84ceb397c', 'a04ee6b0bbd2327b26f0b06e275e0b03']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(235520,1024) == "e5c64c011f9df09a712f0d7b8c3391f6"
}

