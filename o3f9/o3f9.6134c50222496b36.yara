
rule o3f9_6134c50222496b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.6134c50222496b36"
     cluster="o3f9.6134c50222496b36"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lyposit zusy ransom"
     md5_hashes="['62ad1dae78b5bf5c64554cc0aca8c6bc','a174a0f13b16c863c075def3dc38f457','d36de44cb7f0fa90eac2cd05176b6690']"

   strings:
      $hex_string = { cb0ff6757a04c5b5e483bc926d146e9598e876bb978a5ea826019128d8afd2feeac689a7e54ef1fbd6a37f0671a5cf5be3e010c1307832ad8fb34af35f48c0bf }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
