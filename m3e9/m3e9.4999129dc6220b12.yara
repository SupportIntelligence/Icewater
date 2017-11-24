
rule m3e9_4999129dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4999129dc6220b12"
     cluster="m3e9.4999129dc6220b12"
     cluster_size="18"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="injector zusy blackmoon"
     md5_hashes="['0eae4cd016870f772deab6fc148d5649','182b5465c5ff399de22f3bc64c4dabc9','db1529d9af2bb6c513c837766be059d8']"

   strings:
      $hex_string = { 7c32955d5a4afe62f54480206ebb77f91902450aecdee5e709142db07b5731cdb89390c7744ef08a264cb32b2c999ec4aa85ea9b2a1d437d0ce0231aa764fa94 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
