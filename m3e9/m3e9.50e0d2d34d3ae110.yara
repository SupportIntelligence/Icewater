import "hash"

rule m3e9_50e0d2d34d3ae110
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.50e0d2d34d3ae110"
     cluster="m3e9.50e0d2d34d3ae110"
     cluster_size="398 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef pronny"
     md5_hashes="['b99c5dda0eb15f8bf0544b784a8b3d49', 'd7ff4ee207c0d62181b2863a3f384337', 'eb0c0188e9d8a7c1dd3c8d3adc650107']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(118784,1024) == "bf3026b38ac2ed16cef8960af66ceae5"
}

