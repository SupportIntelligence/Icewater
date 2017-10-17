import "hash"

rule n3e9_131ae5a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131ae5a1c2000b32"
     cluster="n3e9.131ae5a1c2000b32"
     cluster_size="433 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple virut rahack"
     md5_hashes="['b9ea15bf79dd2a96d13162d855d4e823', 'c12deb27457a16adff764b479766f0fe', '50ef43335b14204fa8b2450f16428f2b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61952,1024) == "6a039dc6f36c112b920bef9b8a73cb0e"
}

