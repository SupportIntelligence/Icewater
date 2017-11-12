import "hash"

rule p3e9_1adb3929c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.1adb3929c0000b32"
     cluster="p3e9.1adb3929c0000b32"
     cluster_size="1840 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="hupigon backdoor danginex"
     md5_hashes="['19edb5e513b6fd8ef80228fa75b29055', '566f9afe6f65555a5d09d92d4c6522a8', '070943a72876e0f41aee3aebe2345633']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4269056,1024) == "d2dbc238b8a0066d771bbc2982dc0742"
}

