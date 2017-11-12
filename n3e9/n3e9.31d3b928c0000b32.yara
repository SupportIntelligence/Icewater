import "hash"

rule n3e9_31d3b928c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31d3b928c0000b32"
     cluster="n3e9.31d3b928c0000b32"
     cluster_size="589 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['abd42320f4e4a2a5e3280df2a62c8e24', '67fd39b904c6b2c4439ce3d3e9765319', '9a300d4125707c36a77c04adb0a45d20']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(134571,1109) == "5ab5f47638376e909837251fd1657c84"
}

