
rule n3f7_6914428986220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.6914428986220b12"
     cluster="n3f7.6914428986220b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['4cfd514cb8ce3b77dbb483883597986d','66d3511f004075965d31e32705782b0f','e4648931affe37134764b2f43d1f93e4']"

   strings:
      $hex_string = { 352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f5265 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
