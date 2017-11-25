
rule o3e9_4986bccffe630b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4986bccffe630b32"
     cluster="o3e9.4986bccffe630b32"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['02ea486dca79094ca7b66477855c066f','38f4928c5d236c5cdc5cc9368fcd6b5d','debd9efa27a1e65a6402d159ba0d09e8']"

   strings:
      $hex_string = { 2800250064002900110049006e00760061006c0069006400200063006f0064006500200070006100670065000800460065006200720075006100720079000500 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
