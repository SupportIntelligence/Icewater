import "hash"

rule k3e9_50b13136dda31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b13136dda31b32"
     cluster="k3e9.50b13136dda31b32"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1a65d75b0deb4f772fc53bf0918f6e10','59f49b654684f6afda6db9fa1c16bedc','ef83b8314802ad673c160d2be91f2211']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,4096) == "be1070b2c2c331a2fbb604474784a677"
}

