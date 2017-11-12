import "hash"

rule i3ed_053766e7ce208932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.053766e7ce208932"
     cluster="i3ed.053766e7ce208932"
     cluster_size="169"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris symmi gamarue"
     md5_hashes="['0022f0e62012445db0f586117e86c73d','0720057f0f6743b6b80fbd7e410b1b4c','21afc6500cd2df0103a0693c1642b70c']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "73238df589b72e3187ccc4625eb01234"
}

