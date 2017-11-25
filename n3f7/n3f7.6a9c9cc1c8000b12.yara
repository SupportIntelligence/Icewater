
rule n3f7_6a9c9cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.6a9c9cc1c8000b12"
     cluster="n3f7.6a9c9cc1c8000b12"
     cluster_size="51"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['00b599b5bc9ad1d016a8913b22d6a520','020b927277e4012a18ef44a9667145d7','3f4bf915b5055a22cab91362d5c5c820']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c6162656c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
