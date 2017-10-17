import "hash"

rule n3e9_2b1670a2d7bb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1670a2d7bb1932"
     cluster="n3e9.2b1670a2d7bb1932"
     cluster_size="62 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kryptik malicious adload"
     md5_hashes="['322828b5c9a296542ed225374b3637cf', '61f26980a92c2d9e77c1c90dea33e743', 'f5cc35c096f61fb34f4b88ac750523fd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(451584,1024) == "be7f8ddf5ae74f06b4c656f437736d42"
}

