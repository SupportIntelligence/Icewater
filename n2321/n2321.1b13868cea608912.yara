
rule n2321_1b13868cea608912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.1b13868cea608912"
     cluster="n2321.1b13868cea608912"
     cluster_size="153"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="midie dloader genericr"
     md5_hashes="['09d18741d01cb4a9e057b68124be6e3c','09ee7aeae0fa15ea020008fc1c3d0624','2095b2ffa421e477d75baaa5e3dd45c6']"

   strings:
      $hex_string = { 3e425800bcf069f404711f9e596892820ca0109549b065c6d60ddc6455ec77d3150f1821e57a93f86fcfc37c763d25fe8efc5ac567c9af4dac22bf09e2e3e437 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
