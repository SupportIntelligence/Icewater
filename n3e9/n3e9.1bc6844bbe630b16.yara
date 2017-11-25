
rule n3e9_1bc6844bbe630b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc6844bbe630b16"
     cluster="n3e9.1bc6844bbe630b16"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['29cebcf32404dbbaddcbe2b362d4eab9','40ae8d246d6652c84ff8d352561b6a36','f1ae89fec72bc7570c77d187e2a50236']"

   strings:
      $hex_string = { f030000fffffff000000030ffffff0788700330fffff0788e7f0330fffff08888780330fffff08e88780330fffff07ee87f0330ffffff0788703330fffffff00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
