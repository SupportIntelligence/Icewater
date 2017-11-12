import "hash"

rule n3e9_1b1d3ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1d3ec9c4000b32"
     cluster="n3e9.1b1d3ec9c4000b32"
     cluster_size="696 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod jadtre viking"
     md5_hashes="['91b2fa27b52418a7f81d31ce1a333794', 'a5f09320e286daf70f1395f53ad41d0c', '43583049c3994d4e46123322ae0e5076']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(73728,1024) == "1ae1b4bea5700930f760be96978f2f2c"
}

