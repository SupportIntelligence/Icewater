import "hash"

rule n3e9_491c91e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.491c91e9c8800b12"
     cluster="n3e9.491c91e9c8800b12"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="krap symmi malicious"
     md5_hashes="['a3157d5a5d7dc540944018c23e6bb936', 'a9721e60e8686f5fb3e7c80c568bc845', 'a3157d5a5d7dc540944018c23e6bb936']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(411136,1024) == "79bf5d708e51b02933d1018852cb7ad8"
}

