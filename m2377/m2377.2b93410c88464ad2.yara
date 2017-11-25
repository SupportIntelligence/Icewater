
rule m2377_2b93410c88464ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b93410c88464ad2"
     cluster="m2377.2b93410c88464ad2"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['a469d4ffc767fc6b746783a00ec06e21','bd09bfde6529afa71c60126e463e7350','fae498e47edbf37f14eb59b9d3b94e14']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c6162656c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
