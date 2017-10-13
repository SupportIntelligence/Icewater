import "hash"

rule k3e9_6b64d34e8a4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34e8a4b5912"
     cluster="k3e9.6b64d34e8a4b5912"
     cluster_size="32 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c13ea552c9ea9e86941faa6d40202c75', '0e5d095acddf2810a36fd246055eb154', 'cb7c170d5d0c75fd73789d7878272432']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5144,1036) == "bed4364ceb3d7a678c6b4e1366c04d45"
}

