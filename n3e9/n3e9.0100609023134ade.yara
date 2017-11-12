import "hash"

rule n3e9_0100609023134ade
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0100609023134ade"
     cluster="n3e9.0100609023134ade"
     cluster_size="84 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy delf xihet"
     md5_hashes="['b70e76cc1542d4d3f674ca3a5e186b7d', 'ac04eb01833b168d09849ca9f9d40de4', 'af2f55a3cca3f0fe862859e43c50a592']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(183474,1025) == "721b22ad86ada83b32b488884cf97c12"
}

