
rule m3f7_2b93291cca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b93291cca200b12"
     cluster="m3f7.2b93291cca200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['15a075ff523a59278d4722fe2978213b','2d024abdb3beb37501f399ff1104c1c5','4353f9ae756582f6fb3b0e5591a76638']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c6162656c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
