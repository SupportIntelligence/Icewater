
rule m2377_2b93410c88264ad2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b93410c88264ad2"
     cluster="m2377.2b93410c88264ad2"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['121ec2c2f9bc54b7534ace6ac621b779','4801394ad3422555dd27889a2c57415a','df904c9cbb29a8a3eb5e0e0d58541812']"

   strings:
      $hex_string = { 2e676574456c656d656e74427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f736372 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
