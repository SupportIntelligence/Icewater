
rule n3f8_2a146ea5ece10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.2a146ea5ece10b12"
     cluster="n3f8.2a146ea5ece10b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="styricka androidos apprisk"
     md5_hashes="['a716adb55fcb32e805eed4356e7807565b650a8d','9459dcca5f95bfc90b033cf9918e76dac9378354','eb3b0757808a9e556915f0d15a5b59080db3a10b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.2a146ea5ece10b12"

   strings:
      $hex_string = { 9ae7babfe7a88be6938de4bd9c496d706c2e6a6176610004e5a49ae8a18ce8be93e585a50005e5a49ae98089e5afb9e8af9de6a1860004e5a4a7e695b0e6af94 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
