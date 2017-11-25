
rule m3f7_2b931052dba30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b931052dba30b12"
     cluster="m3f7.2b931052dba30b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['027f8ef83c19231dd7b88a82a39be682','5096b37617e6e3a081a762aebfce13f5','a95996df4e692a42b62ddf51c279bb48']"

   strings:
      $hex_string = { 626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f526567697374657257 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
