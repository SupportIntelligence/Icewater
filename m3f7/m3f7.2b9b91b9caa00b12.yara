
rule m3f7_2b9b91b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b9b91b9caa00b12"
     cluster="m3f7.2b9b91b9caa00b12"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['04792b8760892c996893305c4118c597','050dbd4a73c5d4c7404b0d65b58847d2','7113beb17e401b843f16072a2591d183']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c6162656c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57696467 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
