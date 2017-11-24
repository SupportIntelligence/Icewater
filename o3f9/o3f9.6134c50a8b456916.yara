
rule o3f9_6134c50a8b456916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f9.6134c50a8b456916"
     cluster="o3f9.6134c50a8b456916"
     cluster_size="6"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lyposit zusy malicious"
     md5_hashes="['11380b46e6ef6ab47afd041fbbd04c3e','ab5a84b3be2ba1cfcc1116ae31aa2ce9','dd83270457adef25a5d1958f4d9d589f']"

   strings:
      $hex_string = { cb0ff6757a04c5b5e483bc926d146e9598e876bb978a5ea826019128d8afd2feeac689a7e54ef1fbd6a37f0671a5cf5be3e010c1307832ad8fb34af35f48c0bf }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
