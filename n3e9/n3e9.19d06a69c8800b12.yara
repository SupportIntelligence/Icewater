import "hash"

rule n3e9_19d06a69c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.19d06a69c8800b12"
     cluster="n3e9.19d06a69c8800b12"
     cluster_size="195 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy adload malicious"
     md5_hashes="['46d0ce2a80ea3d4e76cf932602957343', '98a3306d0d4a464a54e463df63210d44', 'a6cbb3d77a97a6ec2245cb06bc2346f7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(285696,1024) == "002d0fa77d63d90d994dbc293be8acd9"
}

