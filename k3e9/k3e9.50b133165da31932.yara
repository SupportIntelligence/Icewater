import "hash"

rule k3e9_50b133165da31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b133165da31932"
     cluster="k3e9.50b133165da31932"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['2a38d4726238731c6215f55fe7d2f8e5','4f61f3a374db6f3518d3481b2f8e1abe','e346bd4f21207d208d41e4f48f106d62']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,4096) == "be1070b2c2c331a2fbb604474784a677"
}

