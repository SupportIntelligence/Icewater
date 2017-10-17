import "hash"

rule m3e9_491e5be9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.491e5be9c8000b32"
     cluster="m3e9.491e5be9c8000b32"
     cluster_size="84 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus conjar wbna"
     md5_hashes="['d85e0167ddf88e3d7e293c7d0b2cbb38', 'b1b037deb5207bc18ebbd5823192c4c4', 'c637ccee88719e55f7c75bb95c3e9931']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(39936,1024) == "4b3d71c8bdb189eef5200e3efd80e240"
}

