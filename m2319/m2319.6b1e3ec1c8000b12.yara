
rule m2319_6b1e3ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.6b1e3ec1c8000b12"
     cluster="m2319.6b1e3ec1c8000b12"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['0c00222f634843a28803af0e6e7c6e22','135fd4cb5385288154b3387ce42b5e4f','cd46104c79c60d4b309daaceecf2cff2']"

   strings:
      $hex_string = { 427949642827506f70756c6172506f7374733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
