import "hash"

rule p3e9_1adb3929c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.1adb3929c0000b32"
     cluster="p3e9.1adb3929c0000b32"
     cluster_size="372 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="hupigon backdoor danginex"
     md5_hashes="['b98837b317d31810d661c39d7ee93e99', '371291696cac46ac3478161d9f646ac9', '788137976659a886472b1dc81febb35e']"


   condition:
      filesize > 4194304 and filesize < 16777216
      and hash.md5(4269056,1024) == "d2dbc238b8a0066d771bbc2982dc0742"
}

