
rule j3f0_1716a9cecee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.1716a9cecee31932"
     cluster="j3f0.1716a9cecee31932"
     cluster_size="25"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['04f1b2338933d195ab9afab60afdb64e','2c98d916d3f5f407ffe9a9c9594e588f','c9687d4ad5b6540537f04651d1e8c873']"

   strings:
      $hex_string = { 70356195b6b527fb0f6a5d640cb645f0d3c0f66d0b5202ee3c04264109430f80a240916decf6ed46060630a412462774d5d82d006cff760a50a15844420265db }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
